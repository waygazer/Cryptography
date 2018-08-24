/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptix;


import org.junit.Test;
import static junit.framework.Assert.assertEquals;

public class Base62Test {

	@Test
	public void testCharList() throws Exception {
		StringBuilder sb = new StringBuilder();
		for (char c = 'a'; c <= 'z'; c++) {
			sb.append(c);
		}
		for (char c = 'A'; c <= 'Z'; c++) {
			sb.append(c);
		}
		for (int i = 0; i <= 9; i++) {
			sb.append(i);
		}
		assertEquals(sb.toString(), Base62.ALPHABET);
	}

	@Test
	public void testStringFromInt() throws Exception {
		int n = 0;
		String str = "6JaY2";
		char[] chars = str.toCharArray();
		n += Base62.ALPHABET.indexOf(chars[0]) * (int) Math.pow(62, 4);
		n += Base62.ALPHABET.indexOf(chars[1]) * (int) Math.pow(62, 3);
		n += Base62.ALPHABET.indexOf(chars[2]) * (int) Math.pow(62, 2);
		n += Base62.ALPHABET.indexOf(chars[3]) * (int) Math.pow(62, 1);
		n += Base62.ALPHABET.indexOf(chars[4]) * (int) Math.pow(62, 0);
		assertEquals(str, Base62.fromBase10(n));
	}
	
	@Test
	public void testIntegerFromString() throws Exception {
		assertEquals(125, Base62.toBase10("cb"));
	}

	@Test
	public void testFromZero() {
		assertEquals("a", Base62.fromBase10(0));
		assertEquals("b", Base62.fromBase10(1));
	}
}
