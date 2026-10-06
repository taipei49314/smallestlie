"""SOURCE_ONLY / NOT_RUN: ordinary trusted-writer quota, not a filesystem quota.

Only reviewed writers which call this module are bounded. Test/venv/cache/EC
publication writes and native synchronous IO remain explicit residuals.
"""
from __future__ import annotations
import hashlib
import errno
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
import threading
import time
import types

MIB=1024*1024
TOTAL=256*MIB
PAGE=16*1024
MAX_FILES=64
STATE=struct.Struct('<8sQQQ32s')
MAGIC=b'SLOUT001'
_UNCLOSED_LEDGER=[]  # Failed close is not proved by releasing the Python mutex.
_UNCLOSED_MUTEX=[]  # Exact pending attempts; each retains the original shared custody.
STEPS={'initial-source','initial-status','venv','dependencies','focused','collection','partition','final-source','final-status'}
STAGES=frozenset((*STEPS,'child_cleanup'))
PYTEST_STAGES=frozenset(('focused','collection','partition'))
CAPS={
    'inventory.json':32*MIB,'partition.assignment.json':32*MIB,
    'focused.xml':64*MIB,'partition.xml':64*MIB,
    'parameters.raw.json':4097,'uv.lock.raw':32*MIB+1,'partition-plugin.raw.py':32*MIB+1,
    'requirements.txt':64*1024,
    'result.provisional.json':MIB,'result.commit.tmp':MIB,'result.refused.tmp':MIB,
    'result.pre-refusal.json':MIB,'terminal.json':64*1024,'SUMMARY.md':64*1024,
    'late-refusal.json':4096,'finalization-refusal.json':4096,
}
for _phase in ('focused','collection','partition'):
    CAPS[_phase+'.events.jsonl']=64*MIB
    CAPS[_phase+'.session.json']=64*1024
for _step in STEPS:
    for _stream in ('stdout','stderr'): CAPS[_step+'.'+_stream]=8*MIB+1


# Diagnostics are selected from this source-owned closed vocabulary, never an
# exception message/path/command serialized as an alleged initiating reason.
# Preserve legacy exception text in memory for compatibility only.
_UNCLASSIFIED=('OUTPUT_REFUSAL_UNCLASSIFIED','unclassified','unclassified')
_REFUSALS=types.MappingProxyType({
    'entry deadline before output ledger':('OUTPUT_DEADLINE','ledger','create'),
    'initial ledger short write':('LEDGER_SHORT_WRITE','ledger','create'),
    'unreviewed output writer path':('UNREVIEWED_WRITER','writer','open'),
    'exact finite output attempt':('INVALID_CHARGE','ledger','validate'),
    'entry deadline before output charge':('OUTPUT_DEADLINE','ledger','charge'),
    'output mutex wait refused':('MUTEX_WAIT_EXHAUSTED','mutex','wait'),
    'entry deadline during output lock':('OUTPUT_DEADLINE','file_lock','wait'),
    'original output lock deadline':('FILE_LOCK_WAIT_EXHAUSTED','file_lock','wait'),
    'output ledger partial/extra refused':('LEDGER_LENGTH','ledger','validate'),
    'output ledger raw checksum refused':('LEDGER_CHECKSUM','ledger','validate'),
    'trusted aggregate output attempt quota':('AGGREGATE_QUOTA','ledger','charge'),
    'entry deadline before ledger write':('OUTPUT_DEADLINE','ledger','write'),
    'ledger short write; no payload':('LEDGER_SHORT_WRITE','ledger','write'),
    'late output ledger IO refused':('LATE_LEDGER_IO','ledger','write'),
    'one finite capture read permit':('INVALID_READ_PERMIT','pipe_reader','reserve'),
    'capture sentinel fits finite file':('FILE_CAP','pipe_reader','reserve'),
    'actual observation exceeds paid page':('OBSERVATION_EXCEEDS_PERMIT','pipe_reader','write'),
    'original byte writer required':('INVALID_WRITER','writer','write'),
    'trusted per-file output quota':('FILE_CAP','writer','write'),
    'entry deadline before payload write':('OUTPUT_DEADLINE','writer','write'),
    'unknown payload write count':('UNKNOWN_WRITE_COUNT','writer','write'),
    'short output write; actual prefix retained':('PAYLOAD_SHORT_WRITE','writer','write'),
    'late synchronous payload IO':('LATE_PAYLOAD_IO','writer','write'),
    'entry deadline before flush':('OUTPUT_DEADLINE','writer','flush'),
    'late output flush/close refused':('LATE_CLOSE_IO','writer','close'),
    'genuine JUnit text required':('INVALID_JUNIT_TEXT','junit','write'),
    'exact hash-pinned pytest9.1.1 JUnit provider':('JUNIT_VERSION','junit','configure'),
    'actual genuine LogXML provider required':('JUNIT_OWNER','junit','configure'),
    'reviewed JUnit writer shape':('JUNIT_SHAPE','junit','configure'),
    'exact sole genuine JUnit destination':('JUNIT_DESTINATION','junit','open'),
    'genuine bounded JUnit registration failed':('JUNIT_REGISTRATION','junit','configure'),
    'WHOLE_PHYSICAL_DISK_NOT_ENFORCED: test/temp/venv/EC copies outside trusted writers':
        ('PHYSICAL_QUOTA_UNSUPPORTED','writer','validate'),
    'finite sole output refusal slot':('REFUSAL_SLOT_CAP','refusal_slot','write'),
    'refusal slot partial; prefix retained':('REFUSAL_SLOT_SHORT_WRITE','refusal_slot','write'),
    'stream logical cap plus actual sentinel':('FILE_CAP','pipe_reader','read'),
    'unknown actual pipe observation':('UNKNOWN_PIPE_OBSERVATION','pipe_reader','read'),
    'unconsumed capture read credit':('UNCONSUMED_READ_PERMIT','pipe_reader','read'),
    'pipe completeness/closure unconfirmed':('PIPE_INCOMPLETE','pipe_reader','complete'),
    'native pipe reader/resource closure UNCONFIRMED; holder retained':
        ('PIPE_CLOSURE_UNCONFIRMED','pipe_reader','close'),
    'deadline before child':('STAGE_DEADLINE','child_runner','start'),
    'unknown child return observation':('UNKNOWN_CHILD_RETURN','child_runner','complete'),
    'original entry output deadline changed':('ENTRY_DEADLINE_CHANGED','ledger','validate'),
    'entry output accounting not initialized':('LEDGER_UNINITIALIZED','ledger','validate'),
    'invalid original output deadline':('INVALID_DEADLINE','clock','validate'),
    'invalid original clock observation':('INVALID_CLOCK','clock','validate'),
    'invalid stage owner or identity':('INVALID_STAGE','stage_owner','validate'),
    'invalid stage absolute deadline':('INVALID_STAGE_DEADLINE','stage_owner','validate'),
    'stage deadline before output operation':('STAGE_DEADLINE','stage_owner','acquire'),
    'stage context missing or wrong mode':('INVALID_STAGE_CONTEXT','stage_owner','acquire'),
    'invalid original deadline environment':('INVALID_DEADLINE','stage_owner','acquire'),
    'stage deadline after mutex acquire':('STAGE_DEADLINE','mutex','acquire'),
    'unknown output mutex acquire result':('UNKNOWN_MUTEX_RESULT','mutex','acquire'),
    'unknown output mutex release result':('UNKNOWN_MUTEX_RESULT','mutex','release'),
    'output mutex custody uncertain':('MUTEX_CUSTODY_UNCONFIRMED','mutex','acquire'),
    'invalid output mutex attempt':('INVALID_MUTEX_ATTEMPT','mutex','validate'),
    'stage deadline after file lock acquire':('STAGE_DEADLINE','file_lock','acquire'),
    'late output ledger closure':('LATE_LEDGER_CLOSE','ledger','close'),
    'late output flush':('LATE_FLUSH_IO','writer','flush'),
    'invalid child stage cap or timeout':('INVALID_STAGE_TIMEOUT','child_runner','validate'),
    'entry/output original deadline mismatch':('DEADLINE_MISMATCH','child_runner','validate'),
    'late cleanup return':('STAGE_DEADLINE','child_runner','close'),
})
_DIAGNOSTICS=frozenset((*_REFUSALS.values(),_UNCLASSIFIED))


class OutputRefusal(ValueError):
    def __init__(self,*args):
        message=args[0] if len(args)==1 and type(args[0]) is str else None
        self._output_diagnostic=_REFUSALS.get(message,_UNCLASSIFIED)
        super().__init__(*args)


def refusal_diagnostic(error):
    """Known first-refusal fields only; no arbitrary exception text authority."""
    if type(error) is not OutputRefusal: return None
    observed=getattr(error,'_output_diagnostic',None)
    if (type(observed) is not tuple or len(observed)!=3
            or not all(type(value) is str for value in observed)
            or observed not in _DIAGNOSTICS): observed=_UNCLASSIFIED
    code,operation,stage=observed
    return dict(reason_code=code,operation=operation,stage=stage)


def _require(value,why):
    if not value: raise OutputRefusal(why)


def finite_deadline(value):
    if type(value) not in (int,float): return False
    try: return math.isfinite(value) and value>0
    except OverflowError: return False


def _environment_deadline(value):
    _require(type(value) is str and len(value)<=64
             and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',value) is not None,
             'invalid original deadline environment')
    parsed=float(value)
    _require(finite_deadline(parsed),'invalid original deadline environment')
    return parsed


def _note(primary,error):
    try: BaseException.add_note(primary,'secondary output close: '+type(error).__name__)
    except BaseException: pass


def _encoded(total,files,seq):
    prefix=struct.pack('<8sQQQ',MAGIC,total,files,seq)
    return prefix+hashlib.sha256(prefix).digest()


def _unlock_output_stream(stream):
    """Actual ledger unlock; a seek failure must not suppress stream.close."""
    stream.seek(0)
    if os.name=='nt':
        import msvcrt
        msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
    else:
        import fcntl
        fcntl.flock(stream.fileno(),fcntl.LOCK_UN)


def _acquire_output_mutex(mutex,*,timeout):
    return mutex.acquire(timeout=timeout)


def _release_output_mutex(mutex):
    return mutex.release()


class _MutexAttempt:
    """One caller's retained actual acquisition/known-cleanup invocation."""
    __slots__=('owner','custody','state','primary')
    def __init__(self,owner,custody):
        self.owner,self.custody=owner,custody
        self.state='ACQUIRE_PENDING'; self.primary=None


class _MutexCustody:
    """Shared actual mutex, distinct attempts and irreversible uncertainty.

    No second bookkeeping lock or closure guess. On the required CPython host,
    list append/remove are individual operations; only each attempt's caller
    changes/removes that exact identity. The shared uncertainty only goes False
    to True. An already admitted acquisition can return after another becomes
    uncertain; its own known cleanup cannot retire the other's holder. No new
    admission or ledger work is allowed once uncertainty has been observed.
    """
    __slots__=('_mutex','_uncertain')
    def __init__(self):
        self._mutex=threading.Lock(); self._uncertain=False
    @property
    def mutex(self): return self._mutex
    @property
    def uncertain(self): return self._uncertain
    def begin(self,owner):
        _require(not self.uncertain,'output mutex custody uncertain')
        attempt=_MutexAttempt(owner,self)
        _UNCLOSED_MUTEX.append(attempt)  # Before the one actual acquire.
        if self.uncertain:
            _UNCLOSED_MUTEX.remove(attempt)  # This call never entered acquire.
            raise OutputRefusal('output mutex custody uncertain')
        return attempt
    def acquire(self,attempt):
        _require(type(attempt) is _MutexAttempt and attempt.custody is self
                 and attempt.state=='ACQUIRE_PENDING' and attempt in _UNCLOSED_MUTEX,
                 'invalid output mutex attempt')
        try:
            self.ensure_known()
            remaining=attempt.owner.deadline-attempt.owner._now()
            _require(remaining>0,'entry deadline before output charge')
        except BaseException:
            attempt.state='NOT_ATTEMPTED'; _UNCLOSED_MUTEX.remove(attempt)
            raise  # Actual acquire was never called, so no acquire uncertainty.
        try:
            observed=_acquire_output_mutex(self.mutex,timeout=remaining)
            _require(type(observed) is bool,'unknown output mutex acquire result')
        except BaseException as error:
            self._uncertain=True; attempt.state='ACQUIRE_UNCONFIRMED'; attempt.primary=error
            raise
        if not observed:
            attempt.state='NOT_ACQUIRED'; _UNCLOSED_MUTEX.remove(attempt)
            return False
        attempt.state='ACQUIRED'
        return True
    def release(self,attempt):
        _require(type(attempt) is _MutexAttempt and attempt.custody is self
                 and attempt.state=='ACQUIRED' and attempt in _UNCLOSED_MUTEX,
                 'invalid output mutex attempt')
        try:
            observed=_release_output_mutex(self.mutex)
            _require(observed is None,'unknown output mutex release result')
        except BaseException as error:
            self._uncertain=True; attempt.state='RELEASE_UNCONFIRMED'; attempt.primary=error
            raise
        attempt.state='RELEASED'; _UNCLOSED_MUTEX.remove(attempt)
    def ensure_known(self):
        _require(not self.uncertain,'output mutex custody uncertain')


class OutputBudget:
    """Same entry absolute monotonic deadline; monotone attempted byte charge.

    Ledger writes cost their actual fixed64 bytes before payload. No refund,
    replacement credit, stat-monitor overshoot assertion, or child file handle.
    """
    def __init__(self,out,deadline,*,create=False,work=None,clock=time.monotonic):
        _require(finite_deadline(deadline),'invalid original output deadline')
        self.out=Path(out).resolve(); self.work=None if work is None else Path(work).resolve()
        self.deadline=float(deadline); self.clock=clock; self._mutex_custody=_MutexCustody()
        self.entry_deadline=self.deadline; self.stage_name='entry'
        self.path=self.out/'output-budget.bin'
        if create:
            _require(self.clock()<self.deadline,'entry deadline before output ledger')
            with self.path.open('xb',buffering=0) as stream:
                _require(stream.write(_encoded(STATE.size,1,0))==STATE.size,'initial ledger short write')
                os.fsync(stream.fileno())
    @classmethod
    def child(cls,*,expected_stage):
        stage=os.environ.get('SL_OUTPUT_STAGE')
        _require(type(expected_stage) is str and expected_stage in PYTEST_STAGES
                 and type(stage) is str and stage==expected_stage,'stage context missing or wrong mode')
        entry=_environment_deadline(os.environ.get('SL_OUTPUT_DEADLINE'))
        deadline=_environment_deadline(os.environ.get('SL_OUTPUT_STAGE_DEADLINE'))
        return cls(os.environ['SL_OUTPUT_ROOT'],entry,work=os.environ.get('SL_OUTPUT_WORK')).for_stage(stage,deadline)
    def for_stage(self,stage,deadline):
        _require(type(self) is OutputBudget and self.stage_name=='entry'
                 and type(stage) is str and stage in STAGES,'invalid stage owner or identity')
        _require(finite_deadline(deadline) and deadline<=self.entry_deadline,'invalid stage absolute deadline')
        owner=object.__new__(OutputBudget)
        owner.out,owner.work,owner.path=self.out,self.work,self.path
        owner.clock,owner._mutex_custody=self.clock,self._mutex_custody
        owner.entry_deadline=self.entry_deadline; owner.deadline=float(deadline); owner.stage_name=stage
        owner.ensure_live()
        return owner  # No ledger creation/read/write, new origin, refund or local counter.
    @property
    def mutex(self):
        return self._mutex_custody.mutex
    def _now(self):
        now=self.clock()
        _require(type(now) in (int,float) and math.isfinite(now),'invalid original clock observation')
        return now
    def ensure_live(self):
        now=self._now()
        _require(now<self.deadline,'stage deadline before output operation')
        return now
    def cap(self,path):
        path=Path(path).absolute()
        if self.work is not None and path==self.work/'requirements.txt': return 64*1024
        if path.parent==self.out and re.fullmatch(r'pid-[1-9][0-9]*-taskkill\.(stdout|stderr)',path.name): return 64*1024+1
        if path.parent==self.out and path.name in CAPS: return CAPS[path.name]
        if path.parent==self.out:
            if re.fullmatch(r'[A-Za-z0-9_-]{1,64}\.events\.jsonl',path.name): return 64*MIB
            if re.fullmatch(r'[A-Za-z0-9_-]{1,64}\.session\.json',path.name): return 64*1024
            if re.fullmatch(r'[A-Za-z0-9_-]{1,64}\.assignment\.json',path.name): return 32*MIB
            if re.fullmatch(r'[A-Za-z0-9_-]{1,64}\.xml',path.name): return 64*MIB
        raise OutputRefusal('unreviewed output writer path')
    def charge(self,n,*,new=False):
        _require(type(n) is int and n>=0,'exact finite output attempt')
        remaining=self.deadline-self._now()
        _require(remaining>0,'entry deadline before output charge')
        stream=None; locked=False; primary=None; acquired=False
        custody=self._mutex_custody; attempt=custody.begin(self)
        try:
            acquired=custody.acquire(attempt)
            _require(acquired,'output mutex wait refused')
            custody.ensure_known()
            _require(self._now()<self.deadline,'stage deadline after mutex acquire')
            # Windows production lock. POSIX flock only synthetic source CI.
            stream=self.path.open('r+b',buffering=0)
            while True:
                now=self._now()
                _require(now<self.deadline,'entry deadline during output lock')
                try:
                    stream.seek(0)
                    if os.name=='nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                    locked=True
                    _require(self._now()<self.deadline,'stage deadline after file lock acquire')
                    break
                except OSError as error:
                    if error.errno not in {errno.EACCES,errno.EAGAIN}: raise
                    time.sleep(min(.005,max(0,self.deadline-self._now())))
            stream.seek(0); raw=stream.read(STATE.size+1)
            _require(len(raw)==STATE.size,'output ledger partial/extra refused')
            magic,total,files,seq,sha=STATE.unpack(raw)
            _require(magic==MAGIC and hashlib.sha256(raw[:32]).digest()==sha,'output ledger raw checksum refused')
            total+=n+STATE.size; files+=int(new)
            _require(total<=TOTAL and files<=MAX_FILES,'trusted aggregate output attempt quota')
            _require(self._now()<self.deadline,'entry deadline before ledger write')
            stream.seek(0)
            _require(stream.write(_encoded(total,files,seq+1))==STATE.size,'ledger short write; no payload')
            os.fsync(stream.fileno())
            _require(self._now()<self.deadline,'late output ledger IO refused')
        except BaseException as error: primary=error
        finally:
            try:
                if locked: _unlock_output_stream(stream)
            except BaseException as error:
                if primary is None: primary=error
                else: _note(primary,error)
            try:
                if stream is not None: stream.close()
            except BaseException as error:
                if primary is None: primary=error
                else: _note(primary,error)
                try: _UNCLOSED_LEDGER.append(stream)
                except BaseException as later: _note(primary,later)
            try:
                if acquired: custody.release(attempt)
            except BaseException as error:
                if primary is None: primary=error
                else: _note(primary,error)
            try:
                custody.ensure_known()
            except BaseException as error:
                if primary is None: primary=error
                else: _note(primary,error)
            try: _require(self._now()<self.deadline,'late output ledger closure')
            except BaseException as error:
                if primary is None: primary=error
                else: _note(primary,error)
        if primary is not None: raise primary
    def open(self,path): return BoundedWriter(self,Path(path),self.cap(path))
    def write_new(self,path,raw):
        with self.open(path) as stream: stream.write(raw)


class BoundedWriter:
    def __init__(self,budget,path,cap):
        self.budget,self.path,self.cap=budget,path,cap; self.written=0; self.closed=False
        self.read_credit=0
        budget.charge(0,new=True); self.stream=path.open('xb',buffering=0)
    def reserve_read(self,window):
        _require(not self.read_credit and type(window) is int and 0<window<=PAGE,'one finite capture read permit')
        _require(self.written+window<=self.cap,'capture sentinel fits finite file')
        self.budget.charge(window); self.read_credit=window
    def write_observed(self,raw):
        credit=self.read_credit; self.read_credit=0
        _require(type(raw) is bytes and len(raw)<=credit,'actual observation exceeds paid page')
        return self.write(raw,prepaid=True)
    def write(self,raw,*,prepaid=False):
        _require(type(raw) is bytes and not self.closed,'original byte writer required')
        # Refuse the whole attempted call before any excess payload. Previous
        # calls remain untouched; callers never label that prefix complete.
        _require(self.written+len(raw)<=self.cap,'trusted per-file output quota')
        for start in range(0,len(raw),PAGE):
            page=raw[start:start+PAGE]
            if not prepaid: self.budget.charge(len(page))
            _require(self.budget._now()<self.budget.deadline,'entry deadline before payload write')
            amount=self.stream.write(page)
            _require(type(amount) is int and 0<=amount<=len(page),'unknown payload write count')
            self.written+=amount
            _require(amount==len(page),'short output write; actual prefix retained')
            _require(self.budget._now()<self.budget.deadline,'late synchronous payload IO')
        return len(raw)
    def flush(self):
        _require(self.budget._now()<self.budget.deadline,'entry deadline before flush')
        self.stream.flush()
        _require(self.budget._now()<self.budget.deadline,'late output flush')
    def close(self):
        if self.closed: return
        primary=None
        try: self.stream.flush(); os.fsync(self.stream.fileno())
        except BaseException as error: primary=error
        try: self.stream.close(); self.closed=True
        except BaseException as error:
            if primary is None: primary=error
            else: _note(primary,error)
        try: _require(self.budget._now()<self.budget.deadline,'late output flush/close refused')
        except BaseException as later:
            if primary is None: primary=later
            else: _note(primary,later)
        if primary is not None: raise primary
    def __enter__(self): return self
    def __exit__(self,kind,primary,tb):
        try: self.close()
        except BaseException as error:
            if primary is None: raise
            _note(primary,error)


class BoundedText:
    def __init__(self,writer): self.writer=writer
    def write(self,text):
        _require(type(text) is str,'genuine JUnit text required')
        self.writer.write(text.encode('utf-8')); return len(text)
    def __enter__(self): return self
    def __exit__(self,*args): return self.writer.__exit__(*args)


def close_preserving_primary(writer):
    primary=sys.exception()
    try: writer.close()
    except BaseException as error:
        if primary is None: raise
        _note(primary,error)


def bind_junit(config,budget):
    """Bind ONLY this registered genuine pytest9.1.1 LogXML writer instance.

    Same original function code/report objects/ET tree; only its private globals
    dictionary resolves open to the bounded writer. No module/builtins patch.
    """
    import pytest
    from _pytest import junitxml
    _require(pytest.__version__=='9.1.1','exact hash-pinned pytest9.1.1 JUnit provider')
    owner=config.stash.get(junitxml.xml_key,None)
    _require(type(owner) is junitxml.LogXML,'actual genuine LogXML provider required')
    original=type(owner).pytest_sessionfinish
    _require(original.__module__=='_pytest.junitxml' and 'open' in original.__code__.co_names,'reviewed JUnit writer shape')
    def bounded_open(path,mode,*,encoding):
        _require(Path(path).absolute()==Path(owner.logfile).absolute() and mode=='w' and encoding=='utf-8',
                 'exact sole genuine JUnit destination')
        return BoundedText(budget.open(path))
    namespace=dict(original.__globals__,open=bounded_open)
    copied=types.FunctionType(original.__code__,namespace,original.__name__,original.__defaults__,original.__closure__)
    copied.__kwdefaults__=original.__kwdefaults__
    config.pluginmanager.unregister(owner)
    owner.pytest_sessionfinish=types.MethodType(copied,owner)
    _require(config.pluginmanager.register(owner) is not None,'genuine bounded JUnit registration failed')


def refuse_whole_physical_disk():
    raise OutputRefusal('WHOLE_PHYSICAL_DISK_NOT_ENFORCED: test/temp/venv/EC copies outside trusted writers')


def preserve_refusal(out,value):
    """One separate finite64KiB slot, including actually held unwritten pages.

    This slot is not recycled and is outside the256MiB normal attempt credit.
    Caller guards serialization/write/close failures to retain the primary.
    """
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    _require(len(raw)<=64*1024,'finite sole output refusal slot')
    with (Path(out)/'output-refusal.json').open('xb',buffering=0) as stream:
        for start in range(0,len(raw),PAGE):
            page=raw[start:start+PAGE]
            _require(stream.write(page)==len(page),'refusal slot partial; prefix retained')
        os.fsync(stream.fileno())
