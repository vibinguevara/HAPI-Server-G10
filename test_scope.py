def test_scope():
    scope = "system/*.rs"
    resource = "Patient"
    required_access = "read"
    is_single_patient = False

    for s in scope.split(" "):
        if not s.strip(): continue
        
        first_slash = s.find('/')
        if first_slash == -1: continue
        
        scope_prefix = s[:first_slash]
        rest = s[first_slash+1:]
        
        first_dot = rest.find('.')
        if first_dot == -1: continue
        
        scope_resource = rest[:first_dot]
        access_and_params = rest[first_dot+1:]
        
        first_qm = access_and_params.find('?')
        if first_qm != -1:
            scope_access = access_and_params[:first_qm]
        else:
            scope_access = access_and_params
            
        print(f"prefix: {scope_prefix}, resource: {scope_resource}, access: {scope_access}")
        
        resource_match = scope_resource == "*" or scope_resource == resource
        access_match = False
        
        if scope_access == "*" or scope_access == required_access:
            access_match = True
        elif len(scope_access) > 0 and scope_access not in ("read", "write"):
            if required_access == "read":
                access_match = "r" in scope_access or "s" in scope_access
            elif required_access == "write":
                access_match = "c" in scope_access or "u" in scope_access or "d" in scope_access
                
        print(f"resource_match: {resource_match}, access_match: {access_match}")
        
        if resource_match and access_match:
            if not is_single_patient:
                if scope_prefix == "system":
                    print("AUTHORIZED (!isSingle)")
                    return
            else:
                if scope_prefix in ("system", "patient", "user"):
                    print("AUTHORIZED (isSingle)")
                    return
    print("DENIED")

test_scope()
