#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lower pinned mallocng's hot paths to checked guest-address accesses.

Algorithms are extracted from unmodified source; only address expressions,
memory/atomic accesses and return/slow-path boundaries are adapted. Generated
code remains inspectable in OUT_DIR. No runtime compilation is performed.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / 'upstream/musl-1.2.5'
provenance = json.loads((UP / 'provenance.json').read_text())
for name in ('malloc.c', 'free.c', 'meta.h', 'glue.h'):
    data = (UP / 'mallocng' / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == provenance['files']['src/malloc/mallocng/' + name]
meta = (UP / 'mallocng/meta.h').read_text()
malloc = (UP / 'mallocng/malloc.c').read_text()
free = (UP / 'mallocng/free.c').read_text()

def function(text, name):
    start = text.index('static inline ', text.index(name + '(') - 80)
    opening = text.index('{', text.index(name + '(', start))
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

def change(text, old, new):
    assert old in text, old
    return text.replace(old, new)

def lower(text):
    # Guest addresses are integers throughout; no fabricated host C pointer.
    text = re.sub(r'(?:const )?(?:unsigned char|char|void|struct meta_area|struct meta|struct group)\s*\*', 'uintptr_t ', text)
    for old, new in [
        ('*(const uint16_t *)(p - 2)', 'load(a,p-2,2)'),
        ('*(uint32_t *)(p - 8)', 'load(a,p-8,4)'),
        ('*(uint16_t *)(p-2) = off;', 'store(a,p-2,2,off);'),
        ('*(uint16_t *)(p-2) = (size_t)(p-g->mem->storage)/UNIT;', 'store(a,p-2,2,(size_t)(p-g->mem->storage)/UNIT);'),
        ('*(uint32_t *)(end-4) = reserved;', 'store(a,end-4,4,reserved);'),
        ('end[-reserved] = 0;', 'store(a,end-reserved,1,0);'),
        ('end[-5] = 0;', 'store(a,end-5,1,0);'),
        ('p[-3] = (p[-3]&31) + (reserved<<5);', 'store(a,p-3,1,(p[-3]&31) + (reserved<<5));'),
        ('p[-3] = 7<<5;', 'store(a,p-3,1,7<<5);'),
        ('p[-4] = 0;', 'store(a,p-4,1,0);'),
        ('p[-3] = idx;', 'store(a,p-3,1,idx);'),
    ]:
        text = text.replace(old, new)
    text = text.replace('*(const uint32_t *)(end-4)', 'load(a,end-4,4)').replace('*(uint16_t *)(p-2)', 'load(a,p-2,2)')
    text = re.sub(r'\b(p|end)\[(-[^\]]+)\]', r'load(a,\1+\2,1)', text)
    text = text.replace('*(end-reserved)', 'load(a,end-reserved,1)').replace('*end', 'load(a,end,1)')
    text = text.replace('g->mem->storage', '(field(a,g,16,8)+UNIT)')
    text = text.replace('base->meta', 'load(a,base,8)').replace('area->check', 'load(a,area,8)')
    for obj in ('g', 'meta'):
        for field_name, offset, width in [('mem',16,8),('avail_mask',24,4),('freed_mask',28,4)]:
            text = text.replace(obj+'->'+field_name, f'field(a,{obj},{offset},{width})')
        for field_name, shift, mask in [('last_idx',0,31),('freeable',5,1),('sizeclass',6,63),('maplen',12,0xfffffffffffff)]:
            text = text.replace(obj+'->'+field_name, f'((field(a,{obj},32,8)>>{shift})&{mask}ULL)')
    text = text.replace('ctx.secret', 'load(a,a->context,8)')
    text = text.replace('get_slot_index(p)', 'get_slot_index(a,p)').replace('get_stride(g)', 'get_stride(a,g)')
    text = text.replace('set_size(p, end, n)', 'set_size(a,p, end, n)')
    text = re.sub(r'(get_slot_index|get_meta|get_nominal_size|get_stride|set_size|enframe|size_to_class)\(', r'\1(struct access *a, ', text, count=1)
    assert '->storage' not in text and '->avail_mask' not in text
    return text

classes = re.search(r'const uint16_t size_classes\[\] = \{.*?\};', malloc, re.S).group()
helpers = '\n\n'.join(lower(function(meta, name)) for name in ['get_slot_index','get_meta','get_nominal_size','get_stride','set_size','enframe','size_to_class'])
helpers = re.sub(r'size_classes\[([^\]]+)\]',r'class_value(a,\1)',helpers)
helpers = helpers.replace('static inline void set_size(', 'static inline int set_size(')
helpers = helpers.replace('const uintptr_t base', 'uintptr_t base')
helpers = helpers.replace('\tconst uintptr_t base', '\tuintptr_t base')
# Reject corrupted/extreme offsets before the original signed int multiply.
helpers = helpers.replace('\tuintptr_t base =', '\tassert(offset <= 0x7fffffff/UNIT);\n\tuintptr_t base =')
helpers = helpers.replace('store(a,p-3,1,(load(a,p+-3,1)&31) + (reserved<<5));\n}', 'store(a,p-3,1,(load(a,p+-3,1)&31) + (reserved<<5));\n\treturn 0;\n}')

# Keep the original coarse-class policy and availability loop. An unavailable
# group exits before alloc_slot and before any guest store.
hot = malloc[malloc.index('\tsc = size_to_class(n);', malloc.index('void *malloc')):malloc.index('\tupgradelock();', malloc.index('void *malloc'))]
hot = hot.replace('\trdlock();', '')
hot = change(hot, 'g->avail_mask = mask-first;', 'store(a,g+24,4,mask-first);')
hot = change(hot, 'else if (a_cas(&g->avail_mask, mask, mask-first)!=mask)', 'else if (0)') # upstream glue always has exclusive read locks
hot = change(hot, 'goto success;', 'a->meta=g; a->index=idx; a->counter=load(a,a->context+12,4); return g;')
hot = hot.replace('ctx.active[sc|1]', 'load(a,a->context+80+8*(sc|1),8)')
hot = hot.replace('ctx.active[sc]', 'load(a,a->context+80+8*sc,8)')
hot = hot.replace('ctx.usage_by_class[sc|1]', 'load(a,a->context+464+8*(sc|1),8)')
hot = hot.replace('ctx.usage_by_class[sc]', 'load(a,a->context+464+8*sc,8)')
hot = hot.replace('size_to_class(n)', 'size_to_class(a,n)')
hot = hot.replace('RDLOCK_IS_EXCLUSIVE || !MT', '1')
hot = hot.replace('!load(a,a->context+80+8*(sc|1),8)->avail_mask', '!field(a,load(a,a->context+80+8*(sc|1),8),24,4)')
hot = hot.replace('!load(a,a->context+80+8*(sc|1),8)->freed_mask', '!field(a,load(a,a->context+80+8*(sc|1),8),28,4)')
hot = hot.replace('g->avail_mask', 'field(a,g,24,4)')

# Free's validation and header invalidation are original. Writes are journalled
# until CAS. Slow entry before CAS discards the journal; after a failed CAS it
# resumes at the original wrlock/nontrivial_free boundary with saved g and idx.
body = free[free.index('\tstruct meta *g = get_meta(p);', free.index('void free')):free.index('\twrlock();', free.index('void free'))]
body = body.replace('struct meta *g', 'uintptr_t g')
body = change(body, '((unsigned char *)p)[-3] = 255;', 'store(a,p-3,1,255);')
body = change(body, '*(uint16_t *)((char *)p-2) = 0;', 'store(a,p-2,2,0);')
body = change(body, 'g->freed_mask = freed+self;', 'store(a,g+28,4,freed+self);')
body = change(body, 'a_cas(&g->freed_mask, freed, freed+self)', 'cas(a,g+28,freed,freed+self)')
body = change(body, '\t\treturn;', '\t\treturn 0;')
body = body.replace('get_meta(p)', 'get_meta(a,p)').replace('get_slot_index(p)', 'get_slot_index(a,p)').replace('get_stride(g)', 'get_stride(a,g)').replace('get_nominal_size(p, end)', 'get_nominal_size(a,p, end)')
body = body.replace('unsigned char *', 'uintptr_t ').replace('g->mem->storage', '(field(a,g,16,8)+UNIT)')
body = body.replace('(unsigned char *)p', '(uintptr_t)p')
body = body.replace('g->last_idx', '(field(a,g,32,8)&31)').replace('g->avail_mask','field(a,g,24,4)').replace('g->freed_mask','field(a,g,28,4)')
body = body.replace('!MT', '!a->mt')
# MADV_FREE is disabled by the original pinned glue; omit its dead branch.
start = body.index('\t// release any whole pages')
end = body.index('\t// atomic free without locking')
body = body[:start] + body[end:]
body = body.replace('\tfor (;;) {', '\tfor (unsigned tries=0;;tries++) {\n\t\tif (tries==64) break;')
body += '\n\ta->meta=g; a->index=idx; return 2;\n'

prefix = r'''/* SPDX-License-Identifier: GPL-3.0-or-later
 * Generated from pinned musl mallocng; original algorithm copyright is in
 * upstream/musl-1.2.5/COPYRIGHT. See allocator/generate.py for adaptations. */
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __SIZE_TYPE__ size_t;
#define UNIT 16
#define IB 4
#define MMAP_THRESHOLD 131052
#define a_clz_32(x) __builtin_clz((unsigned)(x))
#define a_ctz_32(x) __builtin_ctz((unsigned)(x))
struct write { uint64_t address, value; uint32_t width, padding; };
struct read_page { uint64_t base; const uint8_t *bytes; };
struct callbacks {
    void *opaque;
    int (*load)(void *, uint64_t, unsigned, uint64_t *);
    int (*cas)(void *, uint64_t, uint32_t, uint32_t, const struct write *, unsigned, uint32_t *);
    int (*read_page)(void *, uint64_t, unsigned, struct read_page *);
};
struct result {
    uint64_t value, meta, index, counter;
    int status;
    unsigned write_count;
    struct write writes[16];
    unsigned load_callbacks, page_callbacks, direct_loads, journal_writes;
};
_Static_assert(sizeof(struct write)==24, "journal ABI");
_Static_assert(__builtin_offsetof(struct result,writes)==40, "result journal ABI");
_Static_assert(__builtin_offsetof(struct result,load_callbacks)==424, "result metrics ABI");
_Static_assert(sizeof(struct result)==440, "result ABI");
struct access {
    const struct callbacks *cb;
    struct result *out;
    uintptr_t context, meta, index, counter;
    int mt, status;
    uintptr_t field_address[4];
    uint64_t field_value[4];
    unsigned field_count;
    struct read_page pages[4];
};
#define assert(x) do { if (!(x)) { a->status=2; return 0; } } while (0)
/* Checked coordinator page borrows are reusable until publication. Worker views
 * disable this capability; every scalar still enters the ordinary CPU transport.
 * Use memcpy for unaligned loads, without creating fabricated C guest pointers. */
static inline __attribute__((always_inline)) int read_scalar(struct access *a, uintptr_t address, unsigned width, uint64_t *out) {
    uint64_t value=0;
    uintptr_t untagged=address & 0x00ffffffffffffffULL;
    uintptr_t base=untagged & -4096ULL;
    unsigned offset=untagged & 4095;
    int direct=0;
    if(a->cb->read_page && width && width<=8 && offset<=4096-width) {
        unsigned slot=(base>>12)&3;
        if(a->pages[slot].base!=base) {
            a->out->page_callbacks++;
            if(a->cb->read_page(a->cb->opaque,address,width,&a->pages[slot])) return 1;
            if(a->pages[slot].base!=base) return 1;
        }
        if(a->pages[slot].bytes) {
            __builtin_memcpy(&value,a->pages[slot].bytes+offset,width);
            a->out->direct_loads++;
            direct=1;
        }
    }
    if(!direct) {
        a->out->load_callbacks++;
        if(a->cb->load(a->cb->opaque,address,width,&value)) return 1;
    }
    /* Preserve original read-after-write behavior without a Rust callback for
     * each staged store. Values remain guest endian; no whole-heap snapshot. */
    for(unsigned w=0;w<a->out->write_count;w++) {
        const struct write *pending=&a->out->writes[w];
        for(unsigned i=0;i<width;i++) {
            uint64_t at=address+i;
            if(at>=pending->address && at-pending->address<pending->width) {
                unsigned shift=8*i;
                uint64_t byte=(pending->value>>(8*(at-pending->address)))&255;
                value=(value & ~(255ULL<<shift)) | (byte<<shift);
            }
        }
    }
    *out=value;
    return 0;
}
/* GNU statement expressions are supported by pinned GCC and Apple Clang.
 * Failures propagate only after callbacks return, without longjmp across Rust. */
#define load(a,p,n) ({ uint64_t tr_value=0; if((a)->status || read_scalar((a),(p),(n),&tr_value)) { (a)->status=1; return 0; } tr_value; })
/* Only nonvolatile mem/control fields may cache values under original musl
 * lifetime/lock rules. Volatile avail/freed masks always read live guest bytes. */
#define field(a,p,o,n) ({ uintptr_t tr_address=(p)+(o); uint64_t tr_result; if((o)==16 || (o)==32) { unsigned tr_i; for(tr_i=0;tr_i<(a)->field_count;tr_i++) if((a)->field_address[tr_i]==tr_address) break; if(tr_i<(a)->field_count) tr_result=(a)->field_value[tr_i]; else { tr_result=load(a,tr_address,n); if((a)->field_count<4) { tr_i=(a)->field_count++; (a)->field_address[tr_i]=tr_address; (a)->field_value[tr_i]=tr_result; } } } else tr_result=load(a,tr_address,n); tr_result; })
#define store(a,p,n,v) do { (a)->field_count=0; unsigned tr_width=(n); if((a)->status || (a)->out->write_count==16 || !(tr_width==1 || tr_width==2 || tr_width==4 || tr_width==8)) { (a)->status=3; return 0; } uint64_t tr_store_address=(p),tr_store_value=(v); (a)->out->writes[(a)->out->write_count]=(struct write){tr_store_address,tr_store_value,tr_width,0}; (a)->out->write_count++; (a)->out->journal_writes++; } while (0)
/* Drop every cached read descriptor before the callback can publish pending
 * headers, detach COW bytes or mutate the freed mask. The callback owner drops
 * its borrows at that same boundary; retries then retranslate current pages. */
#define cas(a,p,o,n) ({ uint32_t tr_value=0; for(unsigned tr_i=0;tr_i<4;tr_i++) (a)->pages[tr_i].base=~0ULL; if((a)->status || (a)->cb->cas((a)->cb->opaque,(p),(o),(n),(a)->out->writes,(a)->out->write_count,&tr_value)) { (a)->status=1; return 0; } (a)->out->write_count=0; tr_value; })
'''
suffix = r'''
static uintptr_t allocate(struct access *a, size_t n) {
    uintptr_t g; uint32_t mask,first; int sc,idx;
'''+hot+r'''
    return 0;
}
static int release(struct access *a, uintptr_t p) {
'''+body+r'''
}
static uintptr_t checked_enframe(struct access *a, uintptr_t g, int index, size_t n, int counter) {
    size_t stride=get_stride(a,g);
    if(a->status) return 0;
    if(stride<IB || stride>131072 || n>stride-IB || index>(int)(field(a,g,32,8)&31)) { a->status=3; return 0; }
    return enframe(a,g,index,n,counter);
}
void trames_native_allocator(const struct callbacks *cb, unsigned op,
        uint64_t pointer_or_size, uint64_t context, int mt, uint64_t index,
        uint64_t counter, struct result *out) {
    struct access a;
    a.cb=cb; a.out=out; a.context=context; a.mt=mt;
    a.meta=a.index=a.counter=0; a.status=0; a.field_count=0;
    for(unsigned i=0;i<4;i++) a.pages[i].base=~0ULL;
    out->write_count=0;
    out->load_callbacks=out->page_callbacks=out->direct_loads=out->journal_writes=0;
    if((op==1 || op==3) && pointer_or_size>=MMAP_THRESHOLD) { out->status=3; return; }
    if(op==3 && index>31) { out->status=3; return; }
    if(op==1) { out->value=allocate(&a,pointer_or_size); out->meta=a.meta; out->index=a.index; out->counter=a.counter; out->status=a.status?a.status:(out->value?0:3); }
    else if(op==3) { out->value=checked_enframe(&a,context,index,pointer_or_size,counter); out->status=a.status; }
    else { out->value=release(&a,pointer_or_size); out->meta=a.meta; out->index=a.index; out->status=a.status; }
}
'''
checked_class = '\n#define class_value(a,i) ({ unsigned tr_class=(i); assert(tr_class<48); size_classes[tr_class]; })\n'
Path(sys.argv[1]).write_text(prefix+classes+'\n'+checked_class+helpers+suffix)
