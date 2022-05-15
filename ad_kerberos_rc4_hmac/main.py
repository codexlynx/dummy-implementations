from actors import KerberosServer, Client, Service

DOMAIN_CONTROLLER = 'dc.example.net'
TARGET_SERVICE = 'http/EXAMPLE.NET'

# Initial status
server = KerberosServer(DOMAIN_CONTROLLER)
service = Service(owner='user2')
client = Client(DOMAIN_CONTROLLER, TARGET_SERVICE, username='user1')

# TGT negotiation
krb_as_req = client.s1_KRB_AS_REQ()
krb_as_rep = server.s2_KRB_AS_REP(krb_as_req)

# TGS negotiation
krb_tgs_req = client.s3_KRB_TGS_REQ(krb_as_rep)
krb_tgs_rep = server.s4_KRB_TGS_REP(krb_tgs_req)

# AP authentication
ap_req = client.s5_AP_REQ(krb_as_rep, krb_tgs_rep)
service.s6_AP_REP(ap_req)