package betatest;

/*
 * $Id: License.java 3271 2008-04-18 20:39:42Z xlv $
 * Copyright (c) 2005-2007 Bruno Lowagie, Carsten Hammer, Paulo Soares
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * This class was originally published under the MPL by Bruno Lowagie,
 * Paulo Soares and Carsten Hammer.
 * It was a part of iText, a Java-PDF library. You can now use it under
 * the MIT License; for backward compatibility you can also use it under
 * the MPL version 1.1: http://www.mozilla.org/MPL/
 * A copy of the MPL license is bundled with the source code FYI.
 */
import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Iterator;

import javax.swing.JInternalFrame;

import com.itextpdf.license.*;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;

public class License {

    public static void main(String[] args) {

        String src  = args[0];
        String dest = args[1];
        String licensekey = args[2];

        LicenseKey.loadLicenseFile(licensekey);
        try {
            PdfReader reader = new PdfReader(src);
            PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest));
            HashMap<String, String> sinfo = reader.getInfo();
//            Iterator<Map.Entry<String, String>> si = sinfo.entrySet().iterator();
//            System.out.println("================================Source Metadata");
//            while (si.hasNext()) {
//                String key = si.next().getKey();
//                System.out.println(key + ", " + sinfo.get(key));
//            }

//            sinfo.put("Title", "Hello World stamped");
//            sinfo.put("Subject", "Hello World with changed metadata"); 
//            sinfo.put("Keywords", "iText in Action, PdfStamper"); 
//            sinfo.put("Creator", "Silly standalone example"); 
//            sinfo.put("Author", "Also Bruno Lowagie");
            sinfo.put("Producer", "AurionPro Solutions; licensed Version");

//            Iterator<Map.Entry<String, String>> di = sinfo.entrySet().iterator();
//            System.out.println("================================Destination Metadata");
//            while (di.hasNext()) {
//                String key = di.next().getKey();
//                System.out.println(key + ", " + sinfo.get(key));
//            }

            stamper.setMoreInfo(sinfo);
            stamper.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (DocumentException ex) {
            ex.printStackTrace();
        }
    }

}
