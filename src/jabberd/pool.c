
#include <lib.h>


pool _pool_new(char *zone) {
  pool p;

  p = (pool)g_malloc0(sizeof(_pool));
  p->lock = g_mutex_new();
  p->pll = NULL;
  return p;
}

void *pmalloc(pool p, int size) {
  void *r;

  if (p == NULL)
    return NULL;

  if (size <= 0)
    return NULL;

  g_mutex_lock(p->lock);
  r = (void *)g_malloc0(size);
  p->pll = g_slist_prepend(p->pll, r);
  g_mutex_unlock(p->lock);
  return r;
}

void *pmalloco(pool p, int size) {
  return pmalloc(p, size);
}

char *pstrdup(pool p, const char *src) {
  char *dest;

  if (src == NULL)
     return NULL;

  dest = pmalloc(p, (strlen(src) + 1));
  memcpy(dest, src, strlen(src));
  return dest;
}

static void jcr_internal_pool_free(gpointer data, gpointer user_data) {
  g_free(data);
}

void pool_free(pool p) {
   if (p == NULL)
      return;

   g_mutex_lock(p->lock);
   g_slist_foreach(p->pll, (void *)jcr_internal_pool_free, NULL);
   g_slist_free(p->pll);
   g_mutex_unlock(p->lock);
   g_mutex_free(p->lock);

   g_free(p);
}
