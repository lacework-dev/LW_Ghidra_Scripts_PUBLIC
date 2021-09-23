//
//@author Lacework Labs
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class HC_Dropper_ID extends GhidraScript {

	
	static String insmod_str = "/sbin/insmod";
	static String ELF = "ELF";
	
	@Override
	protected void run() throws Exception {
		
		Address insmodAddr = find(insmod_str);
		println("[Dropper] insmod string identified at " + insmodAddr.toString());
		Reference[] ref = getReferencesTo(insmodAddr);
		Address insmodInMain = ref[0].getFromAddress();
		println("[Dropper] insmod referenced at "+ insmodInMain.toString());
		println("[Dropper - KO ELF] " + insmodInMain.subtract(14));
		Symbol main =  getSymbolBefore(insmodAddr);
		Address[] embeddedELFs = findBytes(main.getAddress(), ELF, 2);
		
		
		for (int x = 0; x < embeddedELFs.length; x++) {
			println("[+] Found embedded ELF " + embeddedELFs[x].toString());
		}
		
	}
}
