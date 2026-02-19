package device

type Device struct {
	pools pools
}

type pools struct {
	outItemsSynced *WaitPool
	inItemsSynced  *WaitPool
	outItems       *WaitPool
	inItems        *WaitPool
	msgBufs        *WaitPool
}
