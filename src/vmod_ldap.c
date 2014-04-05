#include <stdlib.h>
#include <pthread.h>
#include <syslog.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

//Global rwlock, for all read/modification operations on the data structure
pthread_rwlock_t vmodth_rwlock;
#define LOCK_READ() assert(pthread_rwlock_rdlock(&vmodth_rwlock) == 0);
#define LOCK_WRITE() assert(pthread_rwlock_wrlock(&vmodth_rwlock) == 0);
#define UNLOCK() pthread_rwlock_unlock(&vmodth_rwlock);

// Public: Vmod init function, initialize the data structure

int
init_function(struct vmod_priv *pc, const struct VCL_conf *conf) {
  struct vmodth_priv *priv;

  openlog("libvmod-ldap", LOG_PID, LOG_AUTH);

  syslog(LOG_DEBUG, "libvmod-ldap initializing");

  //Init the rwlock
  pthread_rwlock_init(&vmodth_rwlock, NULL);

  syslog(LOG_DEBUG, "libvmod-ldap initialized");
  return 0;
}

