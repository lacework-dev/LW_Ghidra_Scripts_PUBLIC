//
//@author Lacework Labs
//@category IoC Extraction
//@keybinding
//@menupath
//@toolbar

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public class HCRootkit_Sutersu extends GhidraScript {

	static String vermagic = "vermagic"; // modinfo
	static String kthread = "kthread";

	@Override
	protected void run() throws Exception {
		
		println("Kernel Magic: " + getKernelMagic());
		println("ICMP_INIT: " + getEmbeddedIPv4());
		getEmbeddedIPs();
	}
	
	
	/**
	 * @return string value of kernel magic or error
	 * @throws Exception when .modinfo not found
	 */
	String getKernelMagic() throws Exception{
	try {
			Address verMagicAddr = find(getMemoryBlock(".modinfo").getStart(), vermagic.getBytes());
			return getDataAt(verMagicAddr).getValue().toString();
		} catch (Exception e) {
			return "[!] section \"modinfo\" not identified.";
		}
	}
	
	
	/**
	 * @return Embedded IPs for HC_RK Rookit Sutersu  variant
	 * @throws Exception
	 */
	String getEmbeddedIPv4() throws Exception {
		try {
			List<Symbol> symb = getSymbols("icmp_init", null);
			Address icmpInitAddr = symb.get(0).getAddress();
			return(icmpInitAddr.toString());
		} catch (Exception e) {
			return "[!] Error obtaining embedded IPs";
		}
	}
	
	/**
	 * Identify IPs within Sutersu's .rodata.str1.1 data section
	 * @throws Exception
	 */
	
	void getEmbeddedIPs() throws Exception {
		try {
			Address endOfRoDataSec = getMemoryBlock(".rodata.str1.1").getEnd();
			Address tmpAddr = getDataBefore(endOfRoDataSec).getAddress();
			println("[IPv4]" + getDataBefore(endOfRoDataSec).getValue().toString());
			println("[IPv4]" + getDataBefore(tmpAddr).getValue().toString());
		} catch (Exception e) {
			println("[!] Section not found");
		}
	}
}
