#include <kdb.h>
#include <krb5/kdcpolicy_plugin.h>
#include <krb5/krb5.h>
#include <krb5/plugin.h>
#include <stdint.h>

static krb5_error_code kdcpolicy_tgtguard_check_tgs(
	krb5_context,
	krb5_kdcpolicy_moddata,
	const krb5_kdc_req *,
	const struct _krb5_db_entry_new *,
	const krb5_ticket *,
	const char *const *,
	const char **,
	krb5_deltat *,
	krb5_deltat *);


krb5_error_code kdcpolicy_tgtguard_initvt(
	krb5_context context,
	int maj_ver,
	int min_ver,
	krb5_plugin_vtable vtable)
{
	if (maj_ver != 1)
		return KRB5_PLUGIN_VER_NOTSUPP;

	krb5_kdcpolicy_vtable kdcpolicy_vtable = (krb5_kdcpolicy_vtable) vtable;
	kdcpolicy_vtable->name = "tgtguard";
	kdcpolicy_vtable->check_tgs = kdcpolicy_tgtguard_check_tgs;

	return 0;
}

static krb5_error_code kdcpolicy_tgtguard_check_tgs(
	krb5_context context,
	krb5_kdcpolicy_moddata moddata,
	const krb5_kdc_req *request,
	const struct _krb5_db_entry_new *server,
	const krb5_ticket *ticket,
	const char *const *auth_indicators,
	const char **status,
	krb5_deltat *lifetime_out,
	krb5_deltat *renew_lifetime_out)
{
	krb5_const_principal client;
	krb5_error_code ret;
	krb5_db_entry *client_entry = NULL;
	krb5_timestamp last_password_change;

	if (!ticket || !ticket->enc_part2 || !ticket->enc_part2->client) {
		*status = "TGTGUARD_INVALID_TICKET";
		return KRB5KDC_ERR_POLICY;
	}

	client = ticket->enc_part2->client;
	ret = krb5_db_get_principal(context, client, KRB5_KDB_FLAG_CLIENT, &client_entry);

	if (ret != 0) {
		*status = "TGTGUARD_PRINCIPAL_LOOKUP_FAILED";
		return KRB5KDC_ERR_POLICY;
	}

	ret = krb5_dbe_lookup_last_pwd_change(context, client_entry, &last_password_change);

	if (ret != 0) {
		*status = "TGTGUARD_LAST_PASSWORD_CHANGE_LOOKUP_FAILED";
		return KRB5KDC_ERR_POLICY;
	}

	if (last_password_change == 0) {
		*status = "TGTGUARD_INVALID_LAST_PASSWORD_CHANGE";
		return KRB5KDC_ERR_POLICY;
	}

	if ((uint32_t) ticket->enc_part2->times.authtime <= (uint32_t) last_password_change) {
		*status = "TGTGUARD_REJECT_COMPROMISED_TGT";
		return KRB5KDC_ERR_POLICY;
	}

	return 0;
}
