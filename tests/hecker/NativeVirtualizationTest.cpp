#include <cassert>
// Included after the production pif_prop_virt namespace by the source checker.
extern "C" const prop_info* __system_property_find(const char*) { return nullptr; }
extern "C" void __system_property_read_callback(const prop_info*, void (*)(void*,const char*,const char*,uint32_t), void*) {}
extern "C" int __system_property_foreach(void (*)(const prop_info*,void*),void*) { return 0; }
extern "C" int __system_property_get(const char*,char*) { return 0; }
int main() {
    using namespace pif_prop_virt;
    MapsLine line;
    assert(parseMapsLine("1000-2000 r--s 00000000 00:01 123 /dev/__properties__/u:object_r:default_prop:s0\n", line));
    assert(line.start==0x1000 && line.end==0x2000 && line.inode==123 && line.permissions[3]=='s');
    assert(!parseMapsLine("malformed mapping",line));
    assert(protFromPermissions("r--p")==PROT_READ);
    State state;
    state.exactMap["ro.build.id"]="EXACT";
    state.suffixRules.emplace_back(".id","SUFFIX");
    assert(std::string(overrideFor(state,"ro.build.id"))=="EXACT");
    assert(std::string(overrideFor(state,"ro.vendor.id"))=="SUFFIX");
    assert(overrideFor(state,"ro.product.model")==nullptr);
    alignas(16) unsigned char memory[512]={};
    Mapping mapping;
    mapping.start=reinterpret_cast<uintptr_t>(memory);
    mapping.end=mapping.start+sizeof(memory);
    Override entry{.mapping=&mapping,.offset=128,.name="ro.build.id",.value="TEST"};
    auto* property=reinterpret_cast<InlinePropertyInfo*>(memory+128);
    property->serial=4;
    assert(applyOverride(mapping,entry));
    assert(std::string(property->value)=="TEST");
    assert((property->serial>>24)==4 && !(property->serial&1));
    entry.offset=sizeof(memory)-sizeof(InlinePropertyInfo)+1;
    assert(!applyOverride(mapping,entry));
    puts("Native mapping parser, rule selection and write bounds: PASS");
}
