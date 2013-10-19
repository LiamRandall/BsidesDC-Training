@load base/frameworks/notice
@load base/frameworks/signatures/main
@load base/utils/addrs
@load base/utils/directions-and-hosts

@load-sigs ./lurk0.sig

redef Signatures::ignored_ids += /lurk0/;

module Lurk0;

export {

	redef enum Notice::Type += {
		Lurk0_Client,
		Lurk0_Server

	};

	## Type of Lurk0Host which, on discovery, should raise a notice.
	const notice_lurk0_hosts = LOCAL_HOSTS &redef;

	const notice_lurk0_hosts = LOCAL_HOSTS &redef;

	const lurk0_timeout = 60 mins &redef;
	
	global lurk0_tracker: set[addr];
}


event signature_match(state: signature_state, msg: string, data: string)
	&priority=-5
	{
	if ( /lurk0/ !in state$sig_id ) return;

	if ( state$conn$id$orig_h !in lurk0_tracker )
	{
		add lurk0_tracker[state$conn$id$orig_h];
		NOTICE([$note=Lurk0::Lurk0_Client,
		        $msg=fmt("Probable LURK0 RAT C&C Access: "),
		        $sub=data,
		        $conn=state$conn,
		        $identifier=fmt("%s%s", state$conn$id$orig_h,
		                        state$conn$id$resp_h)]);
	}
	}
