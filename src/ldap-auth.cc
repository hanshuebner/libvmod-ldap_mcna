#include <iostream>
#include <sstream>
#include <map>

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

using namespace std;

extern string base64_decode(const string& input);

class Realm {
private:
  static map<string, Realm*> _realms;

public:
  const string _name;
  const string _ldap_server;
  const string _bind_dn;
  const string _bind_pw;
  const string _base_dn;
  const string _filter_format;

  Realm(const char* name,
        const char* ldap_server,
        const char* bind_dn,
        const char* bind_pw,
        const char* base_dn,
        const char* filter_format)
    : _name(name),
      _ldap_server(ldap_server),
      _bind_dn(bind_dn),
      _bind_pw(bind_pw),
      _base_dn(base_dn),
      _filter_format(filter_format)
  {
    if (_realms.find(_name) != _realms.end()) {
      _realms.erase(_name);
    }
    _realms[_name] = this;
  }

  static const Realm* find(const char* name)
  {
    map<string, Realm*>::const_iterator i = _realms.find(string(name));
    if (i == _realms.end()) {
      return 0;
    } else {
      return (*i).second;
    }
  }
};

map<string, Realm*> Realm::_realms;

#define TIMEOUT 5

static int
ldap_escape_value(char *escaped, int size, const char *src)
{
    int n = 0;
    while (size > 4 && *src) {
        switch (*src) {
        case '*':
        case '(':
        case ')':
        case '\\':
            n += 3;
            size -= 3;
            if (size > 0) {
                *escaped = '\\';
                ++escaped;
                snprintf(escaped, 3, "%02x", (unsigned char) *src);
                ++src;
                escaped += 2;
            }
            break;
        default:
            *escaped = *src;
            ++escaped;
            ++src;
            ++n;
            --size;
        }
    }
    *escaped = '\0';
    return n;
}

static bool
authenticate_ldap(const Realm* realm, const string username, const string password)
{
  char escaped_username[100];
  ldap_escape_value(escaped_username, sizeof escaped_username, username.c_str());
 
  LDAP* ld;
  if (ldap_initialize(&ld, realm->_ldap_server.c_str())) {
    syslog(LOG_ERR, "ldap_initialize failed: %s", strerror(errno));
    return false;
  }
 
  int rc = ldap_simple_bind_s(ld, realm->_bind_dn.c_str(), realm->_bind_pw.c_str());
  if (rc != LDAP_SUCCESS) {
    syslog(LOG_ERR, "ldap_simple_bind_s: %s", ldap_err2string(rc));
    return false;
  }

  char filter[100];
  snprintf(filter, sizeof filter, realm->_filter_format.c_str(), escaped_username);

  char *searchattr[] = { (char *)LDAP_NO_ATTRS, NULL };
  int searchscope = LDAP_SCOPE_SUBTREE;

  LDAPMessage *res = NULL;
  rc = ldap_search_s(ld, realm->_base_dn.c_str(), searchscope, filter, searchattr, 1, &res);
  if (rc != LDAP_SUCCESS) {
    syslog(LOG_ERR, "ldap_search_s: %s", ldap_err2string(rc));
  }

  LDAPMessage *entry = ldap_first_entry(ld, res);
  if (!entry) {
    ldap_msgfree(res);
    syslog(LOG_ERR, "ldap_search_s: no entries");
    return false;
  }

  char *userdn = ldap_get_dn(ld, entry);
  if (!userdn) {
    syslog(LOG_ERR, "could not get user DN for '%s'", username.c_str());
    ldap_msgfree(res);
    return false;
  }

  rc = ldap_simple_bind_s(ld, userdn, password.c_str());

  bool success = (rc == LDAP_SUCCESS);

  ldap_memfree(userdn);
  ldap_msgfree(res);
  ldap_unbind(ld);

  if (success) {
    syslog(LOG_DEBUG, "user '%s' authenticated", username.c_str());
  } else {
    syslog(LOG_WARNING, "user '%s' found, but wrong password", username.c_str());
  }

  return success;
}

bool
authenticate(const Realm* realm, const string username, const string password)
{
  static map<string, time_t> cache;
  string key = username + ":" + password;
  time_t now = time(0);

  map<string, time_t>::iterator entry = cache.find(key);

  if (entry != cache.end() && entry->second < (now - TIMEOUT)) {
    // entry has timed out
    cache.erase(entry);
    entry = cache.end();
  }

  if (entry != cache.end()) {
    syslog(LOG_DEBUG, "authenticate '%s' '%s' => cache hit", realm->_name.c_str(), username.c_str());

    return true;
  } else {
    if (authenticate_ldap(realm, username, password)) {
      cache.insert(pair<string, time_t>(key, now));
      syslog(LOG_DEBUG, "authenticate '%s' '%s' => authenticated & cached", realm->_name.c_str(), username.c_str());
      return true;
    } else {
      syslog(LOG_DEBUG, "authenticate '%s' '%s' => not authenticated", realm->_name.c_str(), username.c_str());
      return false;
    }
  }
}

extern "C" unsigned
vmod_basic_auth(struct sess* sess,
                const char* realm_name,
                const char* authorization_cstr)
{
  const Realm* realm = Realm::find(realm_name);

  if (!realm) {
    syslog(LOG_ERR, "realm '%s' not found", realm_name);
    return 0;
  }

  try {
    const string authorization_str = authorization_cstr;
    const string prefix = "Basic ";
    if (authorization_str.size() < prefix.size() || !equal(prefix.begin(), prefix.end(), authorization_str.begin())) {
      syslog(LOG_WARNING, "invalid Authorization header '%s', does not start with 'Basic '", authorization_str.c_str());
      return 0;
    }

    string authorization = base64_decode(authorization_str.substr(prefix.size()));
    size_t colon = authorization.find(':');
    if (colon == string::npos) {
      syslog(LOG_WARNING, "invalid Authorization header '%s', colon not found", authorization.c_str());
      return 0;
    }

    string username = authorization.substr(0, colon);
    string password = authorization.substr(colon + 1);

    return authenticate(realm, username, password);
  }
  catch (exception& e) {
    ostringstream os;
    os << "exception caught: " << e.what();
    syslog(LOG_WARNING, os.str().c_str());
    return 0;
  }
}

extern "C" void
vmod_make_realm(void* sess,
                const char* name,
                const char* ldap_server,
                const char* bind_dn,
                const char* bind_pw,
                const char* base_dn,
                const char* filter_format)
{
  new Realm(name, ldap_server, bind_dn, bind_pw, base_dn, filter_format);
}
