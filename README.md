# linux-code-injection

## LD_PRELOAD

**HOWTOs**:
* compile: 
  * `gcc -shared -o hook.so hook.c -ldl`
* run: 
  * `LD_PRELOAD=./hook.so ./victim`
* debug: 
  * `gdb -ex 'set env LD_PRELOAD ./hook.so' ./victim`

### hook __libc_start_main
```c
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

int __libc_start_main(
  void *func_ptr,
  int argc,
  char* argv[],
  void (*init_func)(void),
  void (*fini_func)(void),
  void (*rtld_fini_func)(void),
  void *stack_end)
{
    /* do stuffs */
    int (*real__libc_start_main)(void*, int, char**, void(*)(), void(*)(), void(*)(), void*) = dlsym(RTLD_NEXT,"__libc_start_main");
    real__libc_start_main(func_ptr, argc, argv, init_func, fini_func, rtld_fini_func, stack_end);
}
```

### hook rand

#### print all the values returned by rand
```c
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

int rand(void)
{
    // RTLD_NEXT is not posix, to _GNU_SOURCE is needed
    int (*orig_rand)(void) = dlsym(RTLD_NEXT,"rand");
    int rv = orig_rand();
    printf ("%d, ", rv);
    return rv;
}
```

#### replace rand values with fixed one
```c
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

static int next_rand()
{
    /* Put there what sequence of rands you want */
    static int rands[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
    static int cur_rand = 0;

    int rv = rands[cur_rand++];
    cur_rand %= sizeof(rands) / sizeof(rands[0]);
    return rv;
}

int rand(void)
{
    return next_rand();
}

```

## frida

### examples

`pip3 install frida-tools`
* https://learnfrida.info/ : comprehensive guide to learn frida
* https://frida.re/docs/javascript-api/ : everything you can do from js scripts
* https://github.com/frida/frida-python/tree/main/examples
* https://github.com/0xdea/frida-scripts/blob/master/android-snippets/raptor_frida_android_bypass.js : bypass root detection android
* https://github.com/iddoeldor/frida-snippets : frida snippets
* https://github.com/httptoolkit/frida-android-unpinning : certificate pinning bypass

### template

```py
import frida
import sys

def on_message(message, data):
    print(f"[*] {message}")

def create_frida_script(program_name, addr_to_hook, regs_to_read, addresses_to_read):
    script_template = '''
        // Get binary Module: https://frida.re/docs/javascript-api/#process
        let module = Process.getModuleByName("%s")
        
        // Get address of function, need to do this because of ASLR
        let addr = module.base.add(%d)
        
        // Attach to addr
        send("attaching @" + addr)
        
        // intercept a specific address https://frida.re/docs/javascript-api/#interceptor
        Interceptor.attach(addr, {
            onEnter: function(args) {
                %s
                %s
                // console.log(Memory.readByteArray(ptr(this.context.rax),16));
            }
        });
    '''
    regs_fmt = '\n\t\t\t\t'.join(f"send('{reg.upper()} = ' + this.context.{reg.lower()})" for reg in regs_to_read)
    mem_fmt = '\n\t\t\t\t'.join(f"send('{mem} = ' + Memory.readByteArray(ptr({mem}), {nbytes}))" for mem, nbytes in addresses_to_read)
    return script_template % (program_name, addr_to_hook, regs_fmt, mem_fmt)

pid = 1234
session = frida.attach(pid)
script_txt = create_frida_script(
    program_name = 'victim',
    addr_to_hook = 0x1234, # breakpoint address
    regs_to_read = ["rax", "rdx"], # interesting registers
    addresses_to_read = [] # interesting memory
)
script = session.create_script(script_txt)
script.on('message', on_message)
script.load()

sys.stdin.read()
```