#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_gd_info='GoDaddy.com
Site: GoDaddy.com
Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_gd
Options:
 GD_Token Personal Access Token (PAT) with the "domains.dns:update" and "domains.domain:read" scopes
OptionsAlt:
 GD_Key API Key (classic, deprecated by GoDaddy)
 GD_Secret API Secret (classic, deprecated by GoDaddy)
'

GD_Api="https://api.godaddy.com/v1"
GD_Api_v3="https://api.godaddy.com/v3/domains"

# TTL of the TXT records created through the v3 API, which requires one (600 is the minimum)
GD_Ttl_v3=600

########  Public functions #####################

#Usage: add  _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_gd_add() {
  fulldomain=$1
  txtvalue=$2

  if ! _gd_load_credentials; then
    return 1
  fi

  #save the credentials to the account conf file.
  if [ "$_gd_auth" = "token" ]; then
    _saveaccountconf_mutable GD_Token "$GD_Token"
    _clearaccountconf_mutable GD_Key
    _clearaccountconf_mutable GD_Secret
  else
    _saveaccountconf_mutable GD_Key "$GD_Key"
    _saveaccountconf_mutable GD_Secret "$GD_Secret"
    _clearaccountconf_mutable GD_Token
  fi

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi

  _debug _sub_domain "$_sub_domain"
  _debug _domain "$_domain"

  if [ "$_gd_auth" = "token" ]; then
    _gd_v3_add
    return $?
  fi

  _debug "Getting existing records"
  if ! _gd_rest GET "domains/$_domain/records/TXT/$_sub_domain"; then
    return 1
  fi

  if _contains "$response" "$txtvalue"; then
    _info "This record already exists, skipping"
    return 0
  fi

  _add_data="{\"data\":\"$txtvalue\"}"
  for t in $(echo "$response" | tr '{' "\n" | grep "\"name\":\"$_sub_domain\"" | tr ',' "\n" | grep '"data"' | cut -d : -f 2); do
    _debug2 t "$t"
    # ignore empty (previously removed) records, to prevent useless _acme-challenge TXT entries
    if [ "$t" ] && [ "$t" != '""' ]; then
      _add_data="$_add_data,{\"data\":$t}"
    fi
  done
  _debug2 _add_data "$_add_data"

  _info "Adding record"
  if _gd_rest PUT "domains/$_domain/records/TXT/$_sub_domain" "[$_add_data]"; then
    _debug "Checking updated records of '${fulldomain}'"

    if ! _gd_rest GET "domains/$_domain/records/TXT/$_sub_domain"; then
      _err "Validating TXT record for '${fulldomain}' with rest error [$?]." "$response"
      return 1
    fi

    if _contains "$response" "UNKNOWN_DOMAIN"; then
      # GoDaddy sometimes returns UNKNOWN_DOMAIN when reading a record back even
      # though the PUT above succeeded; skip the local readback check and let
      # acme.sh's own DNS propagation check verify the record was published.
      _info "GoDaddy API won't allow reading the record back; skipping local verification."
    elif ! _contains "$response" "$txtvalue"; then
      _err "TXT record '${txtvalue}' for '${fulldomain}', value wasn't set!"
      return 1
    fi
  else
    _err "Add txt record error, value '${txtvalue}' for '${fulldomain}' was not set."
    return 1
  fi

  _sleep 10
  _info "Added TXT record '${txtvalue}' for '${fulldomain}'."
  return 0
}

#fulldomain
dns_gd_rm() {
  fulldomain=$1
  txtvalue=$2

  if ! _gd_load_credentials; then
    return 1
  fi

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi

  _debug _sub_domain "$_sub_domain"
  _debug _domain "$_domain"

  if [ "$_gd_auth" = "token" ]; then
    _gd_v3_rm
    return $?
  fi

  _debug "Getting existing records"
  if ! _gd_rest GET "domains/$_domain/records/TXT/$_sub_domain"; then
    return 1
  fi

  if ! _contains "$response" "$txtvalue"; then
    _info "The record does not exist, skip"
    return 0
  fi

  _add_data=""
  for t in $(echo "$response" | tr '{' "\n" | grep "\"name\":\"$_sub_domain\"" | tr ',' "\n" | grep '"data"' | cut -d : -f 2); do
    _debug2 t "$t"
    if [ "$t" ] && [ "$t" != "\"$txtvalue\"" ]; then
      if [ "$_add_data" ]; then
        _add_data="$_add_data,{\"data\":$t}"
      else
        _add_data="{\"data\":$t}"
      fi
    fi
  done
  if [ -z "$_add_data" ]; then
    # delete empty record
    _debug "Delete last record for '${fulldomain}'"
    if ! _gd_rest DELETE "domains/$_domain/records/TXT/$_sub_domain"; then
      _err "Cannot delete empty TXT record for '$fulldomain'"
      return 1
    fi
  else
    # remove specific TXT value, keeping other entries
    _debug2 _add_data "$_add_data"
    if ! _gd_rest PUT "domains/$_domain/records/TXT/$_sub_domain" "[$_add_data]"; then
      _err "Cannot update TXT record for '$fulldomain'"
      return 1
    fi
  fi
}

####################  Private functions below ##################################

# Loads the credentials from the environment or the account conf file.
# A Personal Access Token (GD_Token) takes precedence over the classic
# GD_Key/GD_Secret pair, unless the pair was given explicitly in the environment.
# sets _gd_auth to "token" or "key"
_gd_load_credentials() {
  if [ -z "$GD_Token" ]; then
    if [ -z "$GD_Key" ] && [ -z "$GD_Secret" ]; then
      GD_Token="$(_readaccountconf_mutable GD_Token)"
    fi
    if [ -z "$GD_Token" ]; then
      GD_Key="${GD_Key:-$(_readaccountconf_mutable GD_Key)}"
      GD_Secret="${GD_Secret:-$(_readaccountconf_mutable GD_Secret)}"
    fi
  fi

  if [ "$GD_Token" ]; then
    _gd_auth="token"
    _debug "Using GoDaddy Personal Access Token (v3 API)"
    return 0
  fi

  if [ "$GD_Key" ] && [ "$GD_Secret" ]; then
    _gd_auth="key"
    _debug "Using GoDaddy classic API key and secret (v1 API)"
    return 0
  fi

  GD_Token=""
  GD_Key=""
  GD_Secret=""
  _err "You didn't specify a GoDaddy Personal Access Token (GD_Token) or api key and secret (GD_Key, GD_Secret) yet."
  _err "Please create your token and try again."
  return 1
}

# Adds the TXT record using the v3 API.
# needs _domain, _sub_domain, fulldomain, txtvalue
_gd_v3_add() {
  _debug "Getting existing records"
  if ! _gd_v3_get_records; then
    return 1
  fi

  if _contains "$response" "$txtvalue"; then
    _info "This record already exists, skipping"
    return 0
  fi

  _info "Adding record"
  _gd_data="{\"name\":\"$_sub_domain\",\"type\":\"TXT\",\"data\":\"$txtvalue\",\"ttl\":$GD_Ttl_v3}"
  if ! _gd_rest POST "zones/$_domain/dns-records" "$_gd_data" || ! _contains "$response" '"recordId"'; then
    if [ "$_gd_code" = "403" ]; then
      _err "Your GoDaddy token is not allowed to change the DNS records of '$_domain'. Make sure it has the \"domains.dns:update\" scope."
    fi
    _err "Add txt record error, value '${txtvalue}' for '${fulldomain}' was not set." "$response"
    return 1
  fi

  _sleep 10
  _info "Added TXT record '${txtvalue}' for '${fulldomain}'."
  return 0
}

# Removes the TXT record using the v3 API.
# needs _domain, _sub_domain, fulldomain, txtvalue
_gd_v3_rm() {
  _debug "Getting existing records"
  if ! _gd_v3_get_records; then
    return 1
  fi

  _record_ids="$(echo "$response" | _normalizeJson | _egrep_o '\{[^{}]*\}' | grep -- "$txtvalue" | _egrep_o '"recordId":"[^"]*"' | cut -d '"' -f 4 | _gd_encode_id)"
  _debug _record_ids "$_record_ids"

  if [ -z "$_record_ids" ]; then
    _info "The record does not exist, skip"
    return 0
  fi

  for _record_id in $_record_ids; do
    if ! _gd_rest DELETE "zones/$_domain/dns-records/$_record_id"; then
      _err "Cannot delete TXT record for '$fulldomain'"
      return 1
    fi
    case "$_gd_code" in
    200 | 204 | 404) ;;
    *)
      _err "Cannot delete TXT record for '$fulldomain'" "$response"
      return 1
      ;;
    esac
  done
  return 0
}

# Percent-encodes a recordId read from stdin, since GoDaddy hands out ids holding
# characters that are JSON escaped or not allowed raw in a URL path, for example
# "<853499546>-[472]-6cf5526d-f17f".
_gd_encode_id() {
  sed -e 's/[\]u00\([0-9a-fA-F][0-9a-fA-F]\)/%\1/g' -e 's/</%3C/g' -e 's/>/%3E/g' -e 's/\[/%5B/g' -e 's/\]/%5D/g'
}

# Lists the TXT records of _sub_domain in the zone _domain using the v3 API.
_gd_v3_get_records() {
  if ! _gd_rest GET "zones/$_domain/dns-records?type=TXT&name=$_sub_domain&pageSize=100"; then
    return 1
  fi
  if ! _contains "$response" '"items"'; then
    _err "Cannot list the TXT records of '$_sub_domain' in zone '$_domain'" "$response"
    return 1
  fi
  return 0
}

#_acme-challenge.www.domain.com
#returns
# _sub_domain=_acme-challenge.www
# _domain=domain.com
_get_root() {
  domain=$1
  i=1
  p=0
  while true; do
    h=$(printf "%s" "$domain" | cut -d . -f "$i"-100)
    if [ -z "$h" ]; then
      #not valid
      return 1
    fi

    # The record name is whatever precedes the candidate zone. Do not assume
    # _acme-challenge here: with DNS alias mode it can be any name, and the
    # record may even sit at the zone apex (name "@").
    if [ "$p" = "0" ]; then
      _probe_sub="@"
    else
      _probe_sub=$(printf "%s" "$domain" | cut -d . -f 1-"$p")
    fi

    if [ "$_gd_auth" = "token" ]; then
      # v3: listing the records of a name that is not a zone of the account
      # answers 400 INVALID_ZONE, so keep walking up until "items" comes back.
      if ! _gd_rest GET "zones/$h/dns-records?type=TXT&pageSize=1"; then
        return 1
      fi
      if _contains "$response" '"items"'; then
        _sub_domain="$_probe_sub"
        _domain="$h"
        return 0
      fi
    else
      # Probe with the records endpoint instead of "GET domains/$h": since
      # 2024-05 GoDaddy rejects the domain details call for accounts with
      # fewer than 10 domains, while record-level calls keep working.
      # https://github.com/acmesh-official/acme.sh/issues/4487
      if ! _gd_rest GET "domains/$h/records/TXT/$_probe_sub"; then
        return 1
      fi
      if _startswith "$response" '\['; then
        _sub_domain="$_probe_sub"
        _domain="$h"
        return 0
      fi

      # Some accounts get UNKNOWN_DOMAIN when reading records of a valid zone
      # even though writes succeed (see issue #6517); fall back to the domain
      # details call for them.
      if ! _gd_rest GET "domains/$h"; then
        return 1
      fi
      if _contains "$response" '"domainId"'; then
        _sub_domain="$_probe_sub"
        _domain="$h"
        return 0
      fi
    fi

    _debug "$h not found"
    p="$i"
    i=$(_math "$i" + 1)
  done
  return 1
}

# sets response and _gd_code (the HTTP status code)
_gd_rest() {
  m=$1
  ep="$2"
  data="$3"
  _debug "$ep"

  if [ "$_gd_auth" = "token" ]; then
    _gd_url="$GD_Api_v3/$ep"
    export _H1="Authorization: Bearer $GD_Token"
  else
    _gd_url="$GD_Api/$ep"
    export _H1="Authorization: sso-key $GD_Key:$GD_Secret"
  fi
  export _H2="Content-Type: application/json"

  if [ "$data" ] || [ "$m" = "DELETE" ]; then
    _debug "data ($m): " "$data"
    response="$(_post "$data" "$_gd_url" "" "$m")"
  else
    response="$(_get "$_gd_url")"
  fi

  if [ "$?" != "0" ]; then
    _err "error on rest call ($m): $ep"
    return 1
  fi
  _gd_code="$(grep "^HTTP" "$HTTP_HEADER" | _tail_n 1 | cut -d " " -f 2 | tr -d "\\r\\n")"
  _debug2 _gd_code "$_gd_code"
  _debug2 response "$response"
  if _contains "$response" "UNABLE_TO_AUTHENTICATE"; then
    _err "It seems that your api key or secret is not correct."
    return 1
  fi
  if [ "$_gd_auth" = "token" ] && [ "$_gd_code" = "401" ]; then
    # A token missing a scope is rejected by the GoDaddy gateway with an empty
    # 401 body, not with the 403 their docs mention, so mention the scopes here.
    _err "It seems that your GoDaddy Personal Access Token is not correct, has expired or lacks the \"domains.dns:update\" and \"domains.domain:read\" scopes."
    _err "Note that a freshly created token needs up to a minute before it is accepted."
    return 1
  fi
  return 0
}
