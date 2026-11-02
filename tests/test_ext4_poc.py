"""Mocked control-plane/fault tests. No Docker, loop, mount or Linux proof here."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ext4_poc', Path(__file__).parents[1]/'scripts/ext4-workspace-poc.py')
poc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(poc)
IMAGE = 'sha256:'+'a'*64
CID = 'b'*64


def container(mount):
    return {'Id':CID, 'Name':'/test', 'Image':IMAGE,
            'Config':{'User':'10001:10001','Labels':{poc.LABEL:'nonce'}},
            'HostConfig':dict(ReadonlyRootfs=True, NetworkMode='none', CgroupnsMode='private',
                             Privileged=False, IpcMode='private', Memory=256*poc.MIB, MemorySwap=256*poc.MIB,
                             CpuPeriod=100000, CpuQuota=25000, PidsLimit=64, ShmSize=8*poc.MIB,
                             CapDrop=['ALL'], CapAdd=None, SecurityOpt=['no-new-privileges:true'],
                             Tmpfs={'/tmp':poc.TMPFS.split(':',1)[1]},
                             LogConfig={'Type':'json-file','Config':{'max-size':'1m','max-file':'2'}}),
            'Mounts':[{'Type':'bind','Source':str(mount),'Destination':'/work','RW':True,'Propagation':'rprivate'}]}


class PolicyTests(unittest.TestCase):
    def test_concurrent_instance_locks_isolate_and_exclude_recovery(self):
        # Real flock calls on temp files; ownership only is mocked for macOS.
        original = os.fstat
        def root_stat(fd):
            s=original(fd)
            return SimpleNamespace(st_uid=0,st_mode=s.st_mode,st_nlink=s.st_nlink)
        with tempfile.TemporaryDirectory() as directory,patch.object(poc.os,'fstat',root_stat):
            first=Path(directory)/'first.lock'; second=Path(directory)/'second.lock'
            fd=poc.acquire_lock(first,True)
            try:
                with self.assertRaises(BlockingIOError): poc.acquire_lock(first,True)
                other=poc.acquire_lock(second,True)
                os.close(other)
            finally: os.close(fd)
            recovered=poc.acquire_lock(first,True); os.close(recovered)

    def test_signal_abort_requests_failed_experiment(self):
        with self.assertRaisesRegex(RuntimeError,'Signal 15'): poc.abort_signal(15,None)

    def test_gate_precedes_any_command(self):
        for disposable, platform, uid in [(False,'linux',0),(True,'darwin',0),(True,'linux',1000)]:
            with self.assertRaises(RuntimeError): poc.gate(disposable,platform,uid)
        poc.gate(True,'linux',0)

    def test_capacity_bytes_and_inodes(self):
        for size, inodes in [(575*poc.MIB,5000),(600*poc.MIB,4095)]:
            with self.assertRaises(RuntimeError):
                poc.capacity(SimpleNamespace(f_bavail=size,f_frsize=1,f_favail=inodes))
        poc.capacity(SimpleNamespace(f_bavail=576*poc.MIB,f_frsize=1,f_favail=4096))

    def test_unsafe_parents_and_symlinks(self):
        for mode, uid in [(stat.S_IFLNK|0o700,0),(stat.S_IFDIR|0o777,0),(stat.S_IFDIR|0o700,501)]:
            with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid)):
                with self.assertRaises(RuntimeError): poc.private_directory('/private/probe')
        for path in ['relative','/','/private/../etc']:
            with self.assertRaises(RuntimeError): poc.private_directory(path)

    def test_backing_rejects_symlink_hardlink_nonroot(self):
        for mode, uid, links in [(stat.S_IFLNK,0,1),(stat.S_IFREG,0,2),(stat.S_IFREG,501,1)]:
            with patch.object(poc.os,'lstat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid,st_nlink=links)):
                with self.assertRaises(RuntimeError): poc.identity('/unused')

    def test_mount_stack_rejected(self):
        line = '42 1 7:0 / /test rw,nosuid,nodev - ext4 /dev/loop0 rw'
        self.assertEqual(poc.mount_record(line,'/test')['id'],'42')
        with self.assertRaises(RuntimeError): poc.mount_record(line+'\n'+line,'/test')

    def test_inspection_rejects_isolation_bypasses(self):
        base=container('/test')
        poc.validate_container(base,Path('/test'))
        mutations = [('ReadonlyRootfs',False),('NetworkMode','host'),('MemorySwap',-1),
                     ('CapAdd',['SYS_ADMIN']),('Privileged',True),('Devices',[{}]),
                     ('DeviceRequests',[{}]),('VolumesFrom',['other']),('PidMode','host'),
                     ('SecurityOpt',[]),('LogConfig',{}),('Tmpfs',{})]
        for key, value in mutations:
            c=copy.deepcopy(base); c['HostConfig'][key]=value
            with self.subTest(key=key), self.assertRaises(RuntimeError): poc.validate_container(c,Path('/test'))
        for m in [{'Type':'volume','Destination':'/escape','RW':True},
                  {'Type':'bind','Destination':'/escape','Source':'/','RW':True},
                  {'Type':'tmpfs','Destination':'/escape','RW':True}]:
            c=copy.deepcopy(base); c['Mounts'].append(m)
            with self.assertRaises(RuntimeError): poc.validate_container(c,Path('/test'))
        for user, volumes in [('0:0',None),('10001:10001',{'/escape':{}})]:
            c=copy.deepcopy(base); c['Config'].update(User=user,Volumes=volumes)
            with self.assertRaises(RuntimeError): poc.validate_container(c,Path('/test'))

    def test_image_volumes_and_unavailable_daemon(self):
        info=dict(OSType='linux',CgroupVersion='2',MemoryLimit=True,SwapLimit=True,
                  CpuCfsQuota=True,CpuCfsPeriod=True,PidsLimit=True)
        def run(args):
            return json.dumps(info if args[1]=='info' else [{'Id':IMAGE,'Config':{'Volumes':{'/escape':{}}}}])
        with self.assertRaises(RuntimeError): poc.preflight(IMAGE,run)
        with self.assertRaises(RuntimeError): poc.preflight('mutable:latest',run)
        with self.assertRaises(OSError): poc.preflight(IMAGE,lambda args: (_ for _ in ()).throw(OSError('offline')))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.calls=[]; self.fail=None; self.live=True; self.attached=True; self.mounted=True
        self.e=poc.Experiment(self.temp.name,self.fake_run)
        self.e.state=dict(schema=1,nonce='nonce',name='test',image_id=IMAGE,container_id=CID,
                          create_attempted=True,loop='/dev/loop0',loop_rdev=os.makedev(7,0),
                          mount_id='42',backing_identity=[1,2],pending=None,tests={},evidence={})
        self.e.image.write_bytes(b'fixture')
        self.e.verify_backing=lambda: None
        self.e.verify_loop=lambda: None
        self.e.verify_mount=lambda: {'line':'mock mountinfo'}
        self.e.mounts=lambda: ''
        self.e.loops=lambda: ([{'name':'/dev/loop0','back-file':str(self.e.image),'back-ino':2,
                               'back-maj:min':'0:1','offset':0,'sizelimit':poc.SIZE}] if self.attached else [])

    def fake_run(self,args):
        self.calls.append(args)
        op=' '.join(args[:2])
        if op==self.fail or args[0]==self.fail: raise RuntimeError('injected '+op)
        if op=='docker inspect':
            if not self.live: raise RuntimeError('not found or daemon unavailable')
            return json.dumps([container(self.e.mount)])
        if op=='docker rm': self.live=False
        if args[0]=='umount': self.mounted=False
        if op=='losetup --detach': self.attached=False
        if op=='docker create': return CID
        if op=='docker wait': return '0'
        if op=='docker logs': return json.dumps({'bytes':'ENOSPC','inodes':{'result':'ENOSPC'}})
        return ''

    def test_success_cleanup_order_and_repeated_recovery(self):
        with patch.object(poc,'identity',return_value=[1,2]): self.e.cleanup()
        self.assertFalse(self.e.image.exists())
        self.assertEqual([a[0] for a in self.calls],['docker','docker','umount','losetup'])
        count=len(self.calls); self.e.cleanup()
        self.assertEqual(len(self.calls),count)

    def test_cleanup_boundary_failures_retain_backing(self):
        for failure in ['docker inspect','docker rm','umount','losetup --detach']:
            with self.subTest(failure=failure):
                self.setUp(); self.fail=failure
                with patch.object(poc,'identity',return_value=[1,2]), self.assertRaises(RuntimeError): self.e.cleanup()
                self.assertTrue(self.e.image.exists())
                self.assertNotIn('unlink',[a[0] for a in self.calls])

    def test_unlink_failure_retains_journal(self):
        original=Path.unlink
        def unlink(path,*args,**kwargs):
            if path==self.e.image: raise OSError('injected unlink')
            return original(path,*args,**kwargs)
        with patch.object(poc,'identity',return_value=[1,2]), patch.object(Path,'unlink',unlink):
            with self.assertRaises(OSError): self.e.cleanup()
        self.assertEqual(self.e.state['pending'],'unlink')
        self.assertTrue(self.e.journal.exists())

    def test_ambiguous_attach_mount_kill_reboot_fail_closed(self):
        for pending in ['attach','mount','remove_container','unmount','detach','unlink']:
            self.e.state.update(pending=pending,create_attempted=False,container_id=None)
            with self.subTest(pending=pending), self.assertRaises(RuntimeError): self.e.cleanup()
            self.assertTrue(self.e.image.exists())
        self.assertEqual(self.calls,[])

    def test_timeout_after_remote_create_reconciles_exact_identity(self):
        self.e.state.update(pending='create',container_id=None)
        with patch.object(poc,'identity',return_value=[1,2]): self.e.cleanup()
        self.assertIn(['docker','rm','-f',CID],self.calls)

    def test_id_reuse_name_collision_and_unknown_ownership(self):
        original=self.e.run
        for key,value in [('Id','c'*64),('Name','/collision'),('Image','sha256:'+'d'*64),('Config',{'Labels':{poc.LABEL:'other'}})]:
            c=container(self.e.mount); c[key]=value
            self.e.run=lambda args: json.dumps([c])
            with self.subTest(key=key),self.assertRaises(RuntimeError): self.e.cleanup()
            self.assertTrue(self.e.image.exists())
        self.e.run=original

    def test_unknown_backing_and_attached_file_never_unlinked(self):
        self.e.state.update(create_attempted=False,container_id=None,loop=None,mount_id=None)
        with patch.object(poc,'identity',return_value=[9,9]),self.assertRaises(RuntimeError): self.e.cleanup()
        with patch.object(poc,'identity',return_value=[1,2]),self.assertRaises(RuntimeError): self.e.cleanup()
        self.assertTrue(self.e.image.exists())

    def test_changed_loop_backing_and_reused_device(self):
        for mutation in [{'back-ino':999},{'back-maj:min':'8:0'},{'offset':4096},{'sizelimit':0},{'back-file':'/unrelated'}]:
            x=self.e.loops()[0]; x.update(mutation)
            with patch.object(self.e,'loops',return_value=[x]),self.assertRaises(RuntimeError):
                poc.Experiment.verify_loop(self.e)
        with patch.object(poc.os,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFBLK,st_rdev=os.makedev(7,1))):
            # Use a valid recorded major/minor for the mock backing dev.
            self.e.state['backing_identity']=[1,2]
            with self.assertRaises(RuntimeError): poc.Experiment.verify_loop(self.e)

    def test_changed_mount_id_device_flags_and_busy_reference(self):
        for line in ['43 1 7:0 / {p} rw,nosuid,nodev - ext4 /dev/loop0 rw',
                     '42 1 7:1 / {p} rw,nosuid,nodev - ext4 /dev/loop1 rw',
                     '42 1 7:0 / {p} rw - ext4 /dev/loop0 rw']:
            with patch.object(self.e,'mounts',return_value=line.format(p=self.e.mount)):
                with self.assertRaises(RuntimeError): poc.Experiment.verify_mount(self.e)
        self.e.state.update(create_attempted=False,container_id=None,mount_id=None)
        self.e.mounts=lambda:'42 1 7:0 / /other rw - ext4 /dev/loop0 rw'
        with self.assertRaisesRegex(RuntimeError,'remains mounted'): self.e.cleanup()
        self.assertTrue(self.e.image.exists())

    def test_mocked_probe_success_records_observed_separately(self):
        with patch.object(poc,'identity',return_value=[1,2]): self.e.launch()
        self.assertEqual(self.e.state['tests']['linux_enforcement'],'PASS')
        self.assertEqual(self.e.state['evidence']['probe']['bytes'],'ENOSPC')
        self.assertIn('docker_inspect',self.e.state['evidence'])

    def test_start_wait_and_create_faults(self):
        for failure in ['docker create','docker start','docker wait']:
            self.fail=failure
            with self.subTest(failure=failure),self.assertRaises(RuntimeError): self.e.launch()
            self.assertTrue(self.e.image.exists())

    def test_setup_fault_boundaries(self):
        # Mock only OS primitives requiring root/Linux; use actual temp files and journal.
        for fail in ['allocate','mkfs.ext4','losetup','mount']:
            with self.subTest(fail=fail),tempfile.TemporaryDirectory() as directory:
                calls=[]
                def run(args):
                    calls.append(args)
                    if args[0]==fail: raise RuntimeError('injected '+fail)
                    return '/dev/loop0' if args[0]=='losetup' else ''
                e=poc.Experiment(directory,run); e.state={'evidence':{},'tests':{}}
                e.verify_backing=lambda: None; e.verify_loop=lambda:None
                def allocate(*args):
                    if fail=='allocate': raise OSError('injected allocation ENOSPC')
                with patch.object(poc,'identity',return_value=[1,2]),patch.object(poc.os,'posix_fallocate',allocate,create=True),patch.object(poc.os,'stat',return_value=SimpleNamespace(st_rdev=os.makedev(7,0))):
                    with self.assertRaises((OSError,RuntimeError)): e.setup()
                self.assertTrue(e.journal.exists())
                self.assertEqual(e.state['pending'],{'allocate':'allocate','mkfs.ext4':'format','losetup':'attach','mount':'mount'}[fail])


if __name__=='__main__': unittest.main()
