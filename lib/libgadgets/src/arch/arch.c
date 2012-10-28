#include <stdio.h>
#include <stdlib.h>

#include "arch/arch.h"
#include "arch/x86/gadgets.h"

struct gadget_plugin_t *current_gadget_plugin;

struct gadget_plugin_t *gadget_plugin_dispatch (int arch)
{
    struct gadget_plugin_t *plugin = gadgets_x86_init();

    return plugin;
}

struct gadget_plugin_t *gadget_plugin_new (void)
{
    struct gadget_plugin_t *plugin;

    plugin = calloc (sizeof(*plugin), 1);
    if (!plugin)
        return NULL;

    //
	plugin->name = NULL;
	plugin->arch = NULL;
	plugin->desc = NULL;

    // methods
	plugin->init = plugin_no_init;
	plugin->fini = plugin_no_fini;
    plugin->find_gadgets = plugin_no_find_gadgets;
    plugin->find_rets = plugin_no_find_rets;
    plugin->find_branches = plugin_no_find_branches;

    return plugin;
}

struct gadget_plugin_t *gadget_plugin_new_copy (struct gadget_plugin_t *plugin)
{
    struct gadget_plugin_t *copy;

    if (!plugin)
        return NULL;

    copy = calloc (sizeof(*copy), 1);
    if (!copy)
        return NULL;

    //
	copy->name = strdup(plugin->name);
	copy->arch = strdup(plugin->arch);
	copy->desc = strdup(plugin->desc);

    // methods
	copy->init = plugin->init;
	copy->fini = plugin->fini;
    copy->find_gadgets = plugin->find_gadgets;
    copy->find_rets = plugin->find_rets;
    copy->find_branches = plugin->find_branches;

    return copy;
}

int gadget_plugin_destroy (struct gadget_plugin_t **plugin)
{
    if (!plugin)
        return -1;
    if (!*plugin)
        return -1;

    free((*plugin)->name);
    free((*plugin)->arch);
    free((*plugin)->desc);
    free(*plugin);
    *plugin = NULL;
}

int plugin_no_init (void)
{
    return 0;
}

int plugin_no_fini (void)
{
    return 0;
}

int plugin_no_find_gadgets (uint8_t *buf, int len)
{
    return 0;
}

struct offsets_t *plugin_no_find_rets (uint8_t *buf, int len)
{
    return NULL;
}

struct offsets_t *plugin_no_find_branches (uint8_t *buf, int len)
{
    return NULL;
}

