#include <stdio.h>
#include <stdlib.h>

#include "arch.h"

struct gadget_plugin_t *current_gadget_plugin;

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

