#include <stdlib.h>
#include <pthread.h>
#include <syslog.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

// FIXME: Locking

// The realms map should be protected so that inserts and lookups
// can't conflict.  There is probably liitle chance that this grows
// into a real problem as people will usually initialize their realms
// from vcl_init, but then, you never know.  This is why the lock
// initialization code below is still here, it needs to be moved to
// ldap-auth.cc and the proper calls need to be added.

// The authentication process itself uses no global resources, so
// there should be no concurrency issues other than the unprotected
// Realm::_realms map.

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

