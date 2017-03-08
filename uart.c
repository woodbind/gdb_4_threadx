void Trid_PutChar(trid_char c) {
	while (!Trid_TX_READY())
		;

	UartspiSend(c);
}

trid_char Trid_GetChar(void) {
	trid_char c;
	while (!Trid_RX_READY())
		;

	UartspiReceive(&c);
	return c;
}

/*******************************************************************************
  and put kgdbcons like this in uart putstring func  
  PutString(char* cp) {

  +int kgdbcons = 0;
  +void Trid_Setkgdbcons(int on){
  +   kgdbcons = on;
  +}
  +
  void Trid_PutString_2(char* cp) {
  +   if (kgdbcons) {
  +       kgdb_console_write(cp, 0); // write log to gdb console
  +       return;
  +   }
  **********************************************/
