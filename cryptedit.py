import sys
import pathlib
import getpass
import tempfile
import pty
from typing import Callable
import zstd
import os
import Cryptodome
import Cryptodome.Cipher
import Cryptodome.Cipher.AES
import Cryptodome.Random
import Cryptodome.Protocol.KDF
import io
import shutil
import traceback
import stat
import subprocess
salt=b'VRv\x17~\xf7\xbd\x95v\x04I\xbbH\xd6L!Eb\xfd\x90{\xa3\xf8L\xbaS\x0b\xfd\xf9\x10JU'
def check_auth(p:str,filepath:pathlib.Path):
    return True
def path_can_exist(filepath:pathlib.Path):
    return True
def read(data_out:list[bytes],readcall:Callable[[int],bytes],lenx:int=4096):
    b=readcall(lenx)
    data_out[0]=b
    return len(data_out[0])
def save_file(textfile:pathlib.Path,cryptfile:pathlib.Path,p:str):
    success=False
    try:
        buffsize=256**3
        with open(str(textfile),'rb') as textio:                            
            with open(str(cryptfile),'wb') as cryptio:
                key=Cryptodome.Protocol.KDF.PBKDF2(p,salt,dkLen=32)                                
                block=textio.read(buffsize)
                while len(block) > 0:
                    compress_bytes=zstd.compress(block,22)                                    
                    blockmemfile=io.BytesIO()
                    cipher = Cryptodome.Cipher.AES.new(key,Cryptodome.Cipher.AES.MODE_EAX)
                    ciphered_block,tag = cipher.encrypt_and_digest(compress_bytes)
                    blockmemfile.write(cipher.nonce)
                    blockmemfile.write(tag)
                    blockmemfile.write(ciphered_block)
                    blockmemfile.flush()
                    cryptblock=blockmemfile.getvalue()
                    cryptlen=len(cryptblock)
                    sizeb=bytearray()
                    for f in reversed(range(0,4)):
                        mask=255
                        mask <<= f*8                                    
                        masked=cryptlen & mask
                        masked >>= f*8
                        sizeb.append(masked)
                    sizeb=bytes(sizeb)
                    sizedcblock=bytearray()
                    sizedcblock.extend(sizeb)
                    sizedcblock.extend(cryptblock)
                    sizedcblock=bytearray(sizedcblock)
                    cryptio.write(sizedcblock)
                    block=textio.read(buffsize)
        success=True
    except Exception as e:
        print('\n'.join(traceback.format_exception(e)))
        print('Unable to write to file.')
    return success
def load_file(textfile:pathlib.Path,cryptfile:pathlib.Path,p:str):
    key=Cryptodome.Protocol.KDF.PBKDF2(p,salt,dkLen=32)      
    success=False
    try:        
        with open(str(textfile),'wb') as textio:                            
            with open(str(cryptfile),'rb') as cryptio:
                key=Cryptodome.Protocol.KDF.PBKDF2(p,salt,dkLen=32)    
                blocksizebytes=cryptio.read(4)
                while len(blocksizebytes) > 0:
                    blocklen=0                    
                    for f in reversed(range(0,4)):
                        f_inv=3-f
                        mask=blocksizebytes[f_inv]
                        mask <<=f*8
                        blocklen |= mask
                    block=cryptio.read(blocklen)
                    if len(block) == blocklen:
                        ramblockfile=io.BytesIO(block)
                        nonce=ramblockfile.read(16)
                        tag=ramblockfile.read(16)
                        ciphered_block=ramblockfile.read()
                        cipher=Cryptodome.Cipher.AES.new(key,Cryptodome.Cipher.AES.MODE_EAX,nonce)
                        decrypted_block=cipher.decrypt_and_verify(ciphered_block,tag)
                        decompressed_block=zstd.decompress(decrypted_block)
                        textio.write(decompressed_block)
                    else:
                        raise Exception('Incomplete block! Partial File!')
                    blocksizebytes=cryptio.read(4)                
        success=True
    except Exception as e:
        print('\n'.join(traceback.format_exception(e)))
        print('Unable to read from file.')
    return success
def main():
    valid_args=False
    if len(sys.argv) == 2:
        valid_args=True
        filename=sys.argv[1]
        filepath=pathlib.Path(filename)
        if (not filepath.exists() and path_can_exist(filepath=filepath)) or filepath.is_file():
            valid_file=True
            if (not filepath.exists() and path_can_exist(filepath=filepath)):                
                new_file=True                
                p=getpass.getpass('Enter Passphrase: ')
                p2=getpass.getpass('Enter Passphrase Again: ')
                auth_success=p==p2                
            else:
                new_file=False
                p=getpass.getpass('Enter Passphrase: ')
                auth_success=check_auth(p=p,filepath=filepath)
        else:
            valid_file=False
    if valid_args and valid_file:
        if auth_success:
            if new_file:
                with tempfile.TemporaryDirectory() as tempdir:                    
                    textfile=pathlib.Path(tempdir,'text.txt')
                    termfile=pathlib.Path(tempdir,'term.bin')
                    scriptfile=pathlib.Path(tempdir,'script.sh')
                    cryptfile=pathlib.Path(tempdir,'crypt.bin')
                                            
                    with open(str(termfile),'wb') as termio:   
                        def read(fd):
                            data = os.read(fd, 1024)
                            termio.write(data)
                            return data  
                        from os import get_terminal_size
                        try:
                            size = get_terminal_size()               
                        except:
                            size=None
                        if isinstance(size,os.terminal_size):
                            script_text='#!/bin/bash' + '\n' + \
                                f'stty rows {size.lines} columns {size.columns}' + '\n' + \
                                f'vi \"{str(textfile)}\"'
                            
                                
                                    
                            try:
                                with open(str(scriptfile),'w') as scriptout:
                                    scriptout.write(script_text)
                                    
                                subprocess.run(['ls','-lha',str(tempdir)])
                                os.chmod(str(scriptfile),stat.S_IEXEC  | stat.S_IXGRP | stat.S_IXOTH | stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
                                subprocess.run(['ls','-lha',str(tempdir)])
                                pty.spawn([str(scriptfile)],read,read)
                                editor_success=True
                            except Exception as e:
                                print('\n'.join(traceback.format_exception(e)))
                                print('Unable to get terminal on this system.')
                                editor_success=False         
                        else:
                            print('Unable to get terminal size.')
                            editor_success=False 
                    if editor_success and save_file(textfile=textfile,cryptfile=cryptfile,p=p):
                        shutil.copyfile(src=str(cryptfile),dst=filename)
                    else:
                        print('Unable to save file. Aborting')
            else:
                with tempfile.TemporaryDirectory() as tempdir:
                    textfile=pathlib.Path(tempdir,'text.txt')
                    termfile=pathlib.Path(tempdir,'term.bin')
                    scriptfile=pathlib.Path(tempdir,'script.sh')
                    cryptfile=pathlib.Path(tempdir,'crypt.bin')
                    shutil.copyfile(src=filename,dst=str(cryptfile))
                    if load_file(str(textfile),str(cryptfile),p):
                        with open(str(termfile),'wb') as termio: 
                            def read(fd):
                                data = os.read(fd, 1024)
                                termio.write(data)
                                return data  
                            from os import get_terminal_size
                            try:
                                size = get_terminal_size()               
                            except:
                                size=None
                            if isinstance(size,os.terminal_size):
                                script_text='#!/bin/bash' + '\n' + \
                                    f'stty rows {size.lines} columns {size.columns}' + '\n' + \
                                    f'vi \"{str(textfile)}\"'
                                
                                    
                                        
                                try:
                                    with open(str(scriptfile),'w') as scriptout:
                                        scriptout.write(script_text)
                                        
                                        
                                    os.chmod(str(scriptfile),stat.S_IEXEC  | stat.S_IXGRP | stat.S_IXOTH | stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
                                    
                                    pty.spawn([str(scriptfile)],read,read)
                                    editor_success=True
                                except Exception as e:
                                    print('\n'.join(traceback.format_exception(e)))
                                    print('Unable to get terminal on this system.')
                                    editor_success=False         
                            else:
                                print('Unable to get terminal size.')
                                editor_success=False 
                        if editor_success and save_file(textfile=textfile,cryptfile=cryptfile,p=p):
                            shutil.copyfile(src=str(cryptfile),dst=filename)
                        else:
                            print('Unable to save file. Aborting')
                    else:
                        print('Unable to load file. Aborting.')
                        
                            
                                      
                                    
                                    
                                    
                                
                                
                                
                                
                                
        else:
            print('Authentication Failed')
    else:
        print('Invalid Path. Must be a regular file or a nonexistent Path')
if __name__ == '__main__':
    main()