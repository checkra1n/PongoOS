#include <pongo.h>
#include <fb.h>

void (*existing_preboot_hook)();

void m_preboot_hook()
{
    puts("Called pre-boot hook");
    /* Do patches here */
    if (existing_preboot_hook != NULL)
    	existing_preboot_hook();
    return;
}

void hello() {
    puts("Hello world!");
        
}

void module_entry() {
    existing_preboot_hook = preboot_hook;
    preboot_hook = m_preboot_hook;
    command_register("hello", "Hello world!", hello);
}

char* module_name = "test_module";

struct pongo_exports exported_symbols[] = {
    {.name = 0, .value = 0}
};
