typedef BOOLEAN (*POLICY_FUNCTION)(VOID *data, UINTN len);

EFI_STATUS
security_policy_install(BOOLEAN (*override)(void), POLICY_FUNCTION allow, POLICY_FUNCTION deny);
EFI_STATUS
security_policy_uninstall(void);
void
security_protocol_set_hashes(unsigned char *esl, int len);
