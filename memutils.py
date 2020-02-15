from ctypes import *
from ctypes.wintypes import *
import psutil
import re
OpenProcess = windll.kernel32.OpenProcess
ReadProcessMemory = windll.kernel32.ReadProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
CloseHandle = windll.kernel32.CloseHandle
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
EnumProcessModules = windll.psapi.EnumProcessModules
GetModuleBaseNameA = windll.psapi.GetModuleBaseNameA

class MemoryUtils:
    
    def __init__(self):
        self.hProcess = None

    def open(self,name):
        pid = self.__get_pid(name)
        if(pid == None):
            raise Exception("Can't find process %s"%s(name))
        self.hProcess = OpenProcess(PROCESS_ALL_ACCESS,False,pid)

    #read value from memory
    def read(self,address,s_type = 'dword'):
        if(self.hProcess == None):
            raise Exception("Non process selected, use open first!!")
        buffer = None
        if( s_type == 'dword' ):
            buffer = c_int(0)
        elif( s_type == 'float' ):
            buffer = c_float(0)
        elif( s_type.startswith('char') or s_type.startswith('byte')):
            m = re.search('(\d{1,})',s_type)
            if(m == None):
                _size = 1
            else:    
                _size = int(m.group(0))
            buffer = (c_char * _size)(0)
        elif(s_type == 'long'):
            buffer = c_long(0)
        else:
            raise Exception('Invalid param type %s'%(s_type))
            
        bytesRead = c_ulong(0)
        data = ReadProcessMemory(self.hProcess,address,byref(buffer),sizeof(buffer),byref(bytesRead))
        if(data):
            if(s_type.startswith('byte')):
                return buffer.value.hex()
            return buffer.value
        else:
            return None

    #write value to memory
    def write(self,address,value,s_type = 'dword'):
        if(self.hProcess == None):
            raise Exception("Non process selected, use open first!!")        
        buffer = None
        bufferSize = 0
        if( s_type == 'dword' ):
            buffer = c_int(value)
            bufferSize = sizeof(buffer)
            buffer = byref(buffer)
        elif( s_type == 'float' ):
            buffer = c_float(value)
            bufferSize = sizeof(buffer)
            buffer = byref(buffer)                
        elif( s_type == 'char' or s_type == 'byte'):
            buffer = c_char_p(value.encode('utf-8'))
            bufferSize = len(value)
        elif(s_type == 'long'):
            buffer = c_long(value)
            bufferSize = sizeof(buffer)
            buffer = byref(buffer)
        else:
            raise Exception('Invalid param type %s'%(s_type))
            
        bytesWritten = c_ulong(0)
        print(bufferSize)
        data = WriteProcessMemory(self.hProcess,address,buffer,bufferSize,byref(bytesWritten))
        if(data):
            if(bytesWritten.value < bufferSize):
                raise Exception ('Error writing all data to memory')
            else:
                return True
        else:
            return False


    def readptr(self,baseAddress,hProc,pointerMap,s_type = "dword"):
        currentAddress = baseAddress
        lastp = pointerMap.pop()
        for p in pointerMap:
            currentAddress = self.read(currentAddress + p,hProc)
        return self.read(currentAddress + lastp,hProc,s_type)

    def writeptr(self,baseAddress,hProc,pointerMap,value,s_type = "dword"):
        currentAddress = baseAddress
        lastp = pointerMap.pop()
        for p in pointerMap:
            currentAddress = self.read(currentAddress + p,hProc)
        return self.write(currentAddress + lastp,hProc,value,s_type)

    def __get_pid(self,process_name):
        for proc in psutil.process_iter():
            if process_name in proc.name():
                return proc.pid
        return None
    def close():
        CloseHandle(self.hProcess)
        self.hProcess = None

    def moduleGetBaseAddress(self,hProc,name):
        name = name.encode("utf-8")
        hModules = (c_size_t * 1024)(0)
        bytesNeeded = c_int(0)
        success = EnumProcessModules(hProcess,byref(hModules),sizeof(hModules),byref(bytesNeeded))
        if(success != 0):
            moduleName = (c_char * 255)(0)
            for i in range(int(bytesNeeded.value / sizeof(c_size_t))):
                success = GetModuleBaseNameA(hProcess,hModules[i],byref(moduleName),255)
                if(success != 0):
                    if(moduleName.value == name):
                        return hModules[i]
                else:
                    raise Exception("Error retrieving module name")
            return None
        else:
            raise Exception("Error enuming process modules")

mem = MemoryUtils()
mem.open("explorer.exe")
print(mem.read(0x0012EBE0))
mem.close()
#hProcess = OpenProcess(PROCESS_ALL_ACCESS,False,pid)
#baseAddress = _MemoryModuleGetBaseAddress(hProcess,"Tutorial-i386.exe")
#print(_MemoryWritePtr(baseAddress,hProcess,[0x00CF7E8,0x170,0x5c8,0x664,0x1f8,0x170],123,"float"))
#CloseHandle(hProcess)
