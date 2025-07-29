package app.rbac.allow

import rego.v1

# Politique principale d'autorisation RBAC
default allow := false

# Autoriser si l'utilisateur a le rôle approprié pour l'action sur la ressource
allow if {
	user_has_permission
}

# Vérifier si l'utilisateur a la permission requise
user_has_permission if {
	# Récupérer les informations de la requête
	user_id := input.user
	action := input.action
	site_id := input.site
	espace := input.espace

	# Récupérer les données utilisateur depuis le service d'autorisation
	user_data := data.users[user_id]
	user_data != null

	# Vérifier les permissions basées sur les rôles
	some role in user_data.roles
	role_has_permission(role, action, site_id, espace)
}

# Définir les permissions par rôle - Admin a accès à tout
role_has_permission("admin", _, _, _)

# Site manager peut lire et écrire sur ses sites gérés
role_has_permission("site_manager", action, site_id, _) if {
	action in ["read", "write"]
	user_data := data.users[input.user]
	some managed_site in user_data.managed_sites
	managed_site == site_id
}

# Invoice user peut lire les factures sur ses sites autorisés
role_has_permission("invoice_user", "read", site_id, "invoices") if {
	site_access_allowed(site_id)
}

# Invoice editor peut lire et écrire les factures sur ses sites autorisés
role_has_permission("invoice_editor", action, site_id, "invoices") if {
	action in ["read", "write"]
	site_access_allowed(site_id)
}

# Vérifier l'accès au site pour l'utilisateur
site_access_allowed(site_id) if {
	user_data := data.users[input.user]
	some allowed_site in user_data.allowed_sites
	allowed_site == site_id
}

# Log des décisions pour le débogage
decision_log := {
	"input": input,
	"user_data": data.users[input.user],
	"timestamp": time.now_ns(),
	"decision": allow,
}
