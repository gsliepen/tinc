#include "config.h"

#include <stdarg.h>

#include <hooks.h>
#include <node.h>

#include "callbacks.h"
#include "process.h"

#include "system.h"

void hook_node_visible(const char *hooktype, va_list ap)
{
  char *name;
  node_t *n;

  n = va_arg(ap, node_t*);
  asprintf(&name, "hosts/%s-down", n->name);
  execute_script(name);
  free(name);
}

void hook_node_invisible(const char *hooktype, va_list ap)
{
  char *name;
  node_t *n;

  n = va_arg(ap, node_t*);
  asprintf(&name, "hosts/%s-up", n->name);
  execute_script(name);
  free(name);
}

void init_callbacks(void)
{
  add_hook("node-visible", hook_node_visible);
  add_hook("node-invisible", hook_node_invisible);
}
