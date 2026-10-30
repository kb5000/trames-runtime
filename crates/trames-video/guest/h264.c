// SPDX-License-Identifier: GPL-3.0-or-later
// VA H.264 metadata plus untouched slice payload -> CoreMedia parameter NALs.
#include "h264.h"
#include <string.h>
#include <limits.h>
typedef struct { uint8_t data[1024]; size_t bits; int error; } Writer;
static void bits(Writer* w, unsigned n, uint32_t value) {
    if (n>32 || w->bits+n>sizeof(w->data)*8) { w->error=1; return; }
    for (unsigned i=n;i;i--) { size_t p=w->bits++; w->data[p/8]|=((value>>(i-1))&1)<<(7-p%8); }
}
static void ue(Writer* w, uint32_t value) {
    if (value==UINT32_MAX) {w->error=1;return;}
    uint32_t v=value+1; unsigned n=0; for (uint32_t x=v;x>>=1;) n++;
    bits(w,n,0);bits(w,n+1,v);
}
static void se(Writer* w, int value) { ue(w,value<=0?(uint32_t)(-value)*2:(uint32_t)value*2-1); }
static size_t nal(Writer* w,uint8_t header,uint8_t* out,size_t capacity) {
    bits(w,1,1); while(w->bits%8)bits(w,1,0);
    if(w->error || !capacity)return 0;
    size_t length=1; out[0]=header;unsigned zeroes=0;
    for(size_t i=0;i<w->bits/8;i++) {
        uint8_t b=w->data[i];
        if(zeroes>=2 && b<=3) {if(length==capacity)return 0;out[length++]=3;zeroes=0;}
        if(length==capacity)return 0;
        out[length++]=b;zeroes=b?0:zeroes+1;
    }
    return length;
}
typedef struct { const uint8_t* bytes;size_t size,position;unsigned left,current,zeroes;int error; } Reader;
static uint32_t get(Reader* r,unsigned n) {
    if(n>32){r->error=1;return 0;}
    uint32_t out=0;
    for(unsigned i=0;i<n;i++) {
        if(!r->left) {
            if(r->position==r->size){r->error=1;return 0;}
            unsigned b=r->bytes[r->position++];
            if(r->zeroes>=2 && b==3) {
                if(r->position==r->size){r->error=1;return 0;}
                b=r->bytes[r->position++];r->zeroes=0;
            }
            r->zeroes=b?0:r->zeroes+1;r->current=b;r->left=8;
        }
        out=(out<<1)|((r->current>>--r->left)&1);
    }
    return out;
}
static uint32_t get_ue(Reader* r) {
    unsigned zeros=0;
    while(!get(r,1) && !r->error) {if(++zeros>30){r->error=1;return 0;}}
    return ((1u<<zeros)-1)+get(r,zeros);
}
int trames_h264_slice(TramesH264* state,const VAPictureParameterBufferH264* p,
    const VASliceParameterBufferH264* slice,const uint8_t* data,size_t size) {
    if(!size || ((data[0]&31)!=1 && (data[0]&31)!=5) || !p->seq_fields.bits.frame_mbs_only_flag ||
       p->seq_fields.bits.pic_order_cnt_type==1 || p->pic_fields.bits.field_pic_flag)return -1;
    Reader r={.bytes=data+1,.size=size-1};
    get_ue(&r);unsigned type=get_ue(&r)%5;
    unsigned pps=get_ue(&r);if(pps>255)return -1;
    state->pps_id=pps;
    get(&r,p->seq_fields.bits.log2_max_frame_num_minus4+4);
    if((data[0]&31)==5)get_ue(&r);
    if(p->seq_fields.bits.pic_order_cnt_type==0) {
        get(&r,p->seq_fields.bits.log2_max_pic_order_cnt_lsb_minus4+4);
        if(p->pic_fields.bits.pic_order_present_flag)get_ue(&r); // signed value has the same codeword length
    }
    if(p->pic_fields.bits.redundant_pic_cnt_present_flag)get_ue(&r);
    if(type==1)get(&r,1);
    if(type==0 || type==1) {
        int override=get(&r,1);
        if(!override) {state->refs[0]=slice->num_ref_idx_l0_active_minus1;if(type==1)state->refs[1]=slice->num_ref_idx_l1_active_minus1;}
    } else if(type!=2) return -1;
    return r.error?-1:0;
}
static const uint8_t zig4[16]={0,1,4,8,5,2,3,6,9,12,13,10,7,11,14,15};
static const uint8_t zig8[64]={0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63};
static void scaling(Writer* w,const uint8_t* list,unsigned count,const uint8_t* zig) {
    bits(w,1,1);int last=8;
    for(unsigned i=0;i<count;i++) {
        int value=list[zig[i]];
        if(!value){w->error=1;return;}
        int delta=(value-last+256)%256;if(delta>127)delta-=256;
        se(w,delta);last=value;
    }
}
int trames_h264_parameters(TramesH264* state,VAProfile profile,unsigned width,unsigned height,
    const VAPictureParameterBufferH264* p,const VAIQMatrixBufferH264* matrix) {
    if(p->bit_depth_luma_minus8 || p->bit_depth_chroma_minus8 || p->seq_fields.bits.chroma_format_idc!=1 ||
       !p->seq_fields.bits.frame_mbs_only_flag || p->seq_fields.bits.pic_order_cnt_type==1 ||
       p->seq_fields.bits.pic_order_cnt_type>2 || p->seq_fields.bits.residual_colour_transform_flag ||
       state->refs[0]>31 || state->refs[1]>31)return -1;
    unsigned cw=(p->picture_width_in_mbs_minus1+1)*16,ch=(p->picture_height_in_mbs_minus1+1)*16;
    if(width>cw || height>ch || width%2 || height%2)return -1;
    int high=profile==VAProfileH264High;
    Writer w={0};
    bits(&w,8,high?100:profile==VAProfileH264Main?77:66);
    bits(&w,8,profile==VAProfileH264ConstrainedBaseline?0xc0:0);
    bits(&w,8,52);ue(&w,0);
    if(high) {ue(&w,1);ue(&w,0);ue(&w,0);bits(&w,1,0);bits(&w,1,0);}
    ue(&w,p->seq_fields.bits.log2_max_frame_num_minus4);
    ue(&w,p->seq_fields.bits.pic_order_cnt_type);
    if(p->seq_fields.bits.pic_order_cnt_type==0)ue(&w,p->seq_fields.bits.log2_max_pic_order_cnt_lsb_minus4);
    ue(&w,p->num_ref_frames);bits(&w,1,p->seq_fields.bits.gaps_in_frame_num_value_allowed_flag);
    ue(&w,p->picture_width_in_mbs_minus1);ue(&w,p->picture_height_in_mbs_minus1);
    bits(&w,1,1);bits(&w,1,p->seq_fields.bits.direct_8x8_inference_flag);
    int crop=width!=cw || height!=ch;bits(&w,1,crop);
    if(crop){ue(&w,0);ue(&w,(cw-width)/2);ue(&w,0);ue(&w,(ch-height)/2);}
    bits(&w,1,0);
    state->sps_size=nal(&w,0x67,state->sps,sizeof(state->sps));
    memset(&w,0,sizeof(w));
    ue(&w,state->pps_id);ue(&w,0);
    bits(&w,1,p->pic_fields.bits.entropy_coding_mode_flag);
    bits(&w,1,p->pic_fields.bits.pic_order_present_flag);ue(&w,0);
    ue(&w,state->refs[0]);ue(&w,state->refs[1]);
    bits(&w,1,p->pic_fields.bits.weighted_pred_flag);bits(&w,2,p->pic_fields.bits.weighted_bipred_idc);
    se(&w,p->pic_init_qp_minus26);se(&w,p->pic_init_qs_minus26);se(&w,p->chroma_qp_index_offset);
    bits(&w,1,p->pic_fields.bits.deblocking_filter_control_present_flag);
    bits(&w,1,p->pic_fields.bits.constrained_intra_pred_flag);
    bits(&w,1,p->pic_fields.bits.redundant_pic_cnt_present_flag);
    if(high) {
        bits(&w,1,p->pic_fields.bits.transform_8x8_mode_flag);
        bits(&w,1,1);
        for(unsigned i=0;i<6;i++)scaling(&w,matrix->ScalingList4x4[i],16,zig4);
        if(p->pic_fields.bits.transform_8x8_mode_flag)for(unsigned i=0;i<2;i++)scaling(&w,matrix->ScalingList8x8[i],64,zig8);
        se(&w,p->second_chroma_qp_index_offset);
    }
    state->pps_size=nal(&w,0x68,state->pps,sizeof(state->pps));
    return state->sps_size && state->pps_size?0:-1;
}
