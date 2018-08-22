//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.5.0.0.1
//
// Copyright 2011 DiceLock Security, LLC. All rights reserved.
//
//                               DISCLAIMER
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// DICELOCK IS A REGISTERED TRADEMARK OR TRADEMARK OF THE OWNERS.
// 
// Environment:
// java version "1.6.0_29"
// Java(TM) SE Runtime Environment (build 1.6.0_29-b11)
// Java HotSpot(TM) Server VM (build 20.4-b02, mixed mode)
// 

package jdigestercheck;


import JHashDigester.CryptoRandomStream.BaseCryptoRandomStream;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.Image;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;


public class DialogResults extends JDialog {
    private Image imageDiceLock = new ImageIcon(JDigesterCheckFrame.class.getResource("dicelock.gif")).getImage();
    private JButton jButtonClose = new JButton();
    private JScrollPane jScrollPaneTableResults = new JScrollPane();
    private DefaultTableModel model = new DefaultTableModel();
    private JTable jTableResults = new JTable(model);

    private String[] comparationResult = new String[2];
    private String[] fixedResultText = new String[3];
    private Character[] hexDigits = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    private String extractedHexHash;


    public DialogResults() {
        this(null, "", false);
    }

    public DialogResults(Frame parent, String title, boolean modal) {
        super(parent, title, modal);
        try {
            jbInit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.setSize(new Dimension(827, 493));
        this.getContentPane().setLayout( null );
        this.setResizable(false);
        jButtonClose.setText("Close");
        jButtonClose.setBounds(new Rectangle(720, 420, 79, 21));
        jButtonClose.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonClose_actionPerformed(e);
                }
            });
        jTableResults.setFillsViewportHeight(true);
        jScrollPaneTableResults.setBounds(new Rectangle(15, 15, 795, 385));
        jScrollPaneTableResults.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        jScrollPaneTableResults.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPaneTableResults.getViewport().add(jTableResults, null);
        this.getContentPane().add(jScrollPaneTableResults, null);
        this.getContentPane().add(jButtonClose, null);
        this.setLocationRelativeTo(jScrollPaneTableResults);
        this.setIconImage(imageDiceLock);
        this.setTitle("JDigesterCheck results");
        model.addColumn(" Algorihm");
        model.addColumn(" Check");
        model.addColumn(" Text & Digest results");
        ((DefaultTableCellRenderer)jTableResults.getTableHeader().getDefaultRenderer()).setHorizontalAlignment(JLabel.LEFT);


        jTableResults.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int vColIndexAlg = 0;
        TableColumn colAlg = jTableResults.getColumnModel().getColumn(vColIndexAlg);
        colAlg.setPreferredWidth(130);

        int vColIndexCmp = 1;
        TableColumn colCmp = jTableResults.getColumnModel().getColumn(vColIndexCmp);
        colCmp.setPreferredWidth(60);

        int vColIndexRes = 2;
        TableColumn colRes = jTableResults.getColumnModel().getColumn(vColIndexRes);
        colRes.setPreferredWidth(1000);
        
        // Comparison results
        comparationResult[0] = "<html><span style=\"color:green; font-weight: bold;\">OK</span></html>";
        comparationResult[1] = "<html><span style=\"color:red; font-weight: bold;\">Wrong</span></html>";
        
        // Fixed result text
        fixedResultText[0] = "Text digested: ";
        fixedResultText[1] = "Expected digest: ";
        fixedResultText[2] = "Computed digest: ";
    }

    private void jButtonClose_actionPerformed(ActionEvent e) {
        this.dispose();
    }
    
    public void resetDialog() {
        model.getDataVector().removeAllElements();
        model.fireTableDataChanged();    
    }
    
    private String extractHexadecimal(BaseCryptoRandomStream stream) {
        short  i;
        short  c;

        extractedHexHash = "";
        for ( i = 0; i < stream.GetUCLength(); i++ ) {
            c = (byte)stream.GetUCPosition(i);
            extractedHexHash = extractedHexHash + hexDigits[ (c >>> 4) & 0x0F ].toString();
            extractedHexHash = extractedHexHash + hexDigits[ c & 0x0F ].toString();
        }
        return extractedHexHash;
    }
    
    public void AddResult(String algorithm, String text, String expected, BaseCryptoRandomStream computed) {
        String compared;
        String hexadecimalHash;
        
        model.addRow(new Object[]{"<html><span style=\"font-weight: bold;\">" + algorithm + "</span></html>", "", ""});
        model.addRow(new Object[]{fixedResultText[0], "", text});
        model.addRow(new Object[]{fixedResultText[1], "", expected});
        hexadecimalHash = extractHexadecimal(computed);
        if ( expected.equals(hexadecimalHash) ) {
            compared = comparationResult[0];
        }
        else {
            compared = comparationResult[1];
        }
        model.addRow(new Object[]{fixedResultText[2], compared, extractedHexHash});
        model.addRow(new Object[]{"", "", ""});
        model.fireTableDataChanged();
    }
}
