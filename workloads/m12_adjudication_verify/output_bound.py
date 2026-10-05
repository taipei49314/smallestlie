"""SOURCE_ONLY / NOT_RUN: ordinary trusted-writer quota, not a filesystem quota.

Only reviewed writers which call this module are bounded. Test/venv/cache/EC
publication writes and native synchronous IO remain explicit residuals.
"""
from __future__ import annotations
import hashlib
import json
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
STEPS={'initial-source','initial-status','venv','dependencies','focused','collection','partition','final-source','final-status'}
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


class OutputRefusal(ValueError): pass


def _require(value,why):
    if not value: raise OutputRefusal(why)


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


class OutputBudget:
    """Same entry absolute monotonic deadline; monotone attempted byte charge.

    Ledger writes cost their actual fixed64 bytes before payload. No refund,
    replacement credit, stat-monitor overshoot assertion, or child file handle.
    """
    def __init__(self,out,deadline,*,create=False,work=None,clock=time.monotonic):
        self.out=Path(out).resolve(); self.work=None if work is None else Path(work).resolve()
        self.deadline=float(deadline); self.clock=clock; self.mutex=threading.Lock()
        self.path=self.out/'output-budget.bin'
        if create:
            _require(self.clock()<self.deadline,'entry deadline before output ledger')
            with self.path.open('xb',buffering=0) as stream:
                _require(stream.write(_encoded(STATE.size,1,0))==STATE.size,'initial ledger short write')
                os.fsync(stream.fileno())
    @classmethod
    def child(cls):
        return cls(os.environ['SL_OUTPUT_ROOT'],os.environ['SL_OUTPUT_DEADLINE'],work=os.environ.get('SL_OUTPUT_WORK'))
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
        remaining=self.deadline-self.clock()
        _require(remaining>0 and self.mutex.acquire(timeout=min(.2,remaining)),'output lock/deadline refused')
        stream=None; locked=False; primary=None
        try:
            # Windows production lock. POSIX flock only synthetic source CI.
            stream=self.path.open('r+b',buffering=0)
            end=min(self.deadline,self.clock()+.2)
            while True:
                _require(self.clock()<end,'original output lock deadline')
                try:
                    stream.seek(0)
                    if os.name=='nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                    locked=True; break
                except OSError: time.sleep(min(.005,max(0,end-self.clock())))
            stream.seek(0); raw=stream.read(STATE.size+1)
            _require(len(raw)==STATE.size,'output ledger partial/extra refused')
            magic,total,files,seq,sha=STATE.unpack(raw)
            _require(magic==MAGIC and hashlib.sha256(raw[:32]).digest()==sha,'output ledger raw checksum refused')
            total+=n+STATE.size; files+=int(new)
            _require(total<=TOTAL and files<=MAX_FILES,'trusted aggregate output attempt quota')
            _require(self.clock()<self.deadline,'entry deadline before ledger write')
            stream.seek(0)
            _require(stream.write(_encoded(total,files,seq+1))==STATE.size,'ledger short write; no payload')
            os.fsync(stream.fileno())
            _require(self.clock()<self.deadline,'late output ledger IO refused')
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
            try: self.mutex.release()
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
            _require(self.budget.clock()<self.budget.deadline,'entry deadline before payload write')
            amount=self.stream.write(page)
            _require(type(amount) is int and 0<=amount<=len(page),'unknown payload write count')
            self.written+=amount
            _require(amount==len(page),'short output write; actual prefix retained')
            _require(self.budget.clock()<self.budget.deadline,'late synchronous payload IO')
        return len(raw)
    def flush(self):
        _require(self.budget.clock()<self.budget.deadline,'entry deadline before flush')
        self.stream.flush()
    def close(self):
        if self.closed: return
        primary=None
        try: self.stream.flush(); os.fsync(self.stream.fileno())
        except BaseException as error: primary=error
        try: self.stream.close(); self.closed=True
        except BaseException as error:
            if primary is None: primary=error
            else: _note(primary,error)
        if self.budget.clock()>=self.budget.deadline:
            later=OutputRefusal('late output flush/close refused')
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
