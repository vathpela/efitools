typedef BOOLEAN (*POLICY_FUNCTION)(VOID *data, UINTN len);

EFI_STATUS
security_policy_install(BOOLEAN (*override)(void), POLICY_FUNCTION allow, POLICY_FUNCTION deny);
EFI_STATUS
security_policy_uninstall(void);
void
security_protocol_set_hashes(unsigned char *esl, int len);

/* three policies for MoK based on hashes only */
BOOLEAN security_policy_mok_override(void);
BOOLEAN security_policy_mok_deny(VOID *data, UINTN len);
BOOLEAN security_policy_mok_allow(VOID *data, UINTN len);
