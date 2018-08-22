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


import JHashDigester.CryptoRandomStream.DefaultCryptoRandomStream;
import JHashDigester.Hash.HashSuite;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Image;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import java.io.IOException;

import java.net.URI;
import java.net.URISyntaxException;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;


public class JDigesterCheckFrame extends JFrame {
    private BorderLayout layoutMain = new BorderLayout();
    private JPanel panelCenter = new JPanel();
    private JMenuBar menuBar = new JMenuBar();
    private JMenu menuFile = new JMenu();
    private JMenuItem menuFileExit = new JMenuItem();
    private JMenu menuHelp = new JMenu();
    private JMenuItem menuHelpAbout = new JMenuItem();
    private JMenuItem jMenuItemDiceLockWebSite = new JMenuItem();
    private JLabel statusBar = new JLabel();
    private Image imageDiceLock = new ImageIcon(JDigesterCheckFrame.class.getResource("dicelock.gif")).getImage();
    private JPanel jPanelSelectHashes = new JPanel();
    private JButton jButtonClose = new JButton();
    private JPanel jPanelSelectInputData = new JPanel();
    private JTabbedPane jTabbedPaneSelectInputData = new JTabbedPane();
    private JPanel jPanelSha32Data = new JPanel();
    private JPanel jPanelSha64Data = new JPanel();
    private JPanel jPanelRipemdData = new JPanel();
    private JCheckBox jCheckBoxRipemdData1 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData2 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData3 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData4 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData5 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData6 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData7 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData8 = new JCheckBox();
    private JCheckBox jCheckBoxRipemdData9 = new JCheckBox();
    private JCheckBox jCheckBoxSha32Data1 = new JCheckBox();
    private JCheckBox jCheckBoxSha32Data2 = new JCheckBox();
    private JCheckBox jCheckBoxSha32Data3 = new JCheckBox();
    private JCheckBox jCheckBoxSha64Data1 = new JCheckBox();
    private JCheckBox jCheckBoxSha64Data2 = new JCheckBox();
    private JCheckBox jCheckBoxSha64Data3 = new JCheckBox();
    private JCheckBox jCheckBoxSha1 = new JCheckBox();
    private JCheckBox jCheckBoxSha224 = new JCheckBox();
    private JCheckBox jCheckBoxSha256 = new JCheckBox();
    private JCheckBox jCheckBoxSha384 = new JCheckBox();
    private JCheckBox jCheckBoxSha512 = new JCheckBox();
    private JCheckBox jCheckBoxRipemd128 = new JCheckBox();
    private JCheckBox jCheckBoxRipemd160 = new JCheckBox();
    private JCheckBox jCheckBoxRipemd256 = new JCheckBox();
    private JCheckBox jCheckBoxRipemd320 = new JCheckBox();
    private JButton jButtonHashSelectAll = new JButton();
    private JButton jButtonHashDeselectAll = new JButton();
    private JButton jButtonRipemdSelectAll = new JButton();
    private JButton jButtonRipemdDeselectAll = new JButton();
    private JButton jButtonSha32SelectAll = new JButton();
    private JButton jButtonSha32DeselectAll = new JButton();
    private JButton jButtonSha64SelectAll = new JButton();
    private JButton jButtonSha64DeselectAll = new JButton();
    private JLabel jLabelSha64DataLabel_2_1 = new JLabel();
    private DialogResults dialogResults = new DialogResults();


    private HashSuite hashSuite = new HashSuite();

    private DefaultCryptoRandomStream digestSha1;
    private DefaultCryptoRandomStream digestSha224;
    private DefaultCryptoRandomStream digestSha256;
    private DefaultCryptoRandomStream digestSha384;
    private DefaultCryptoRandomStream digestSha512;
    private DefaultCryptoRandomStream digestRipemd128;
    private DefaultCryptoRandomStream digestRipemd160;
    private DefaultCryptoRandomStream digestRipemd256;
    private DefaultCryptoRandomStream digestRipemd320;

    private DefaultCryptoRandomStream[] data_sha_32 = new DefaultCryptoRandomStream[3];
    private DefaultCryptoRandomStream[] data_sha_64 = new DefaultCryptoRandomStream[3];
    private DefaultCryptoRandomStream[] data_ripemd = new DefaultCryptoRandomStream[9];
    
    private String[] hashAlgorithms = new String[9];

    private String[] label_sha_32 = new String[3];
    private String[] label_sha_64 = new String[3];
    private String[] label_ripemd = new String[9];
    private String[] expected_sha_1 = new String[3];
    private String[] expected_sha_224 = new String[3];
    private String[] expected_sha_256 = new String[3];
    private String[] expected_sha_384 = new String[3];
    private String[] expected_sha_512 = new String[3];
    private String[] expected_ripemd_128 = new String[9];
    private String[] expected_ripemd_160 = new String[9];
    private String[] expected_ripemd_256 = new String[9];
    private String[] expected_ripemd_320 = new String[9];
    private JButton jButtonReset = new JButton();
    private JButton jButtonRunHashes = new JButton();
    private JProgressBar jProgressBarHashExecution = new JProgressBar();

    /**
     * @param args
     */
    public static void main(String[] args) {
        new JDigesterCheckFrame();
    }

    public JDigesterCheckFrame() {
        try {
            jbInit();
            this.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            this.setVisible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void jbInit() throws Exception {
        this.setJMenuBar( menuBar );
        this.getContentPane().setLayout( layoutMain );
        panelCenter.setLayout( null );
        this.setSize(new Dimension(843, 573));
        menuFile.setText( "File" );
        menuFileExit.setText( "Exit" );
        menuFileExit.addActionListener( new ActionListener() { public void actionPerformed( ActionEvent ae ) { fileExit_ActionPerformed( ae ); } } );
        menuHelp.setText( "Help" );
        menuHelpAbout.setText( "About" );
        menuHelpAbout.addActionListener( new ActionListener() { public void actionPerformed( ActionEvent ae ) { helpAbout_ActionPerformed( ae ); } } );
        jMenuItemDiceLockWebSite.setText("DiceLock Security, LCC");
        jMenuItemDiceLockWebSite.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
                    try {
                        jMenuItemDiceLockWebSite_actionPerformed(e);
                    } catch (URISyntaxException f) {
                    } catch (IOException f) {
                    }
                }
        });
        statusBar.setText( "" );
        jPanelSelectHashes.setBounds(new Rectangle(10, 10, 245, 395));
        jPanelSelectHashes.setBorder(BorderFactory.createTitledBorder("Select Hash Algorithms"));
        jPanelSelectHashes.setLayout(null);
        jButtonClose.setText("Close");
        jButtonClose.setBounds(new Rectangle(735, 485, 79, 21));
        jButtonClose.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonClose_actionPerformed(e);
                }
            });
        jPanelSelectInputData.setBounds(new Rectangle(265, 10, 565, 395));
        jPanelSelectInputData.setBorder(BorderFactory.createTitledBorder("Select hash algorithm test input data"));
        jPanelSelectInputData.setLayout(null);
        jPanelSelectInputData.setFont(new Font("Dialog", 0, 10));
        jTabbedPaneSelectInputData.setBounds(new Rectangle(15, 25, 535, 355));
        jPanelSha32Data.setFont(new Font("Dialog", 0, 10));
        jPanelSha32Data.setLayout(null);
        jPanelSha64Data.setLayout(null);
        jPanelRipemdData.setLayout(null);
        jCheckBoxRipemdData1.setText("\"\" (empty string)");
        jCheckBoxRipemdData1.setBounds(new Rectangle(30, 15, 240, 20));
        jCheckBoxRipemdData1.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData2.setText("\"a\"");
        jCheckBoxRipemdData2.setBounds(new Rectangle(30, 49, 240, 20));
        jCheckBoxRipemdData2.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData3.setText("\"abc\"");
        jCheckBoxRipemdData3.setBounds(new Rectangle(30, 84, 245, 20));
        jCheckBoxRipemdData3.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData4.setText("\"message digest\"");
        jCheckBoxRipemdData4.setBounds(new Rectangle(30, 118, 250, 20));
        jCheckBoxRipemdData4.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData5.setText("\"abcdefghijklmnopqrstuvwxyz\"");
        jCheckBoxRipemdData5.setBounds(new Rectangle(30, 153, 245, 20));
        jCheckBoxRipemdData5.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData6.setText("\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"");
        jCheckBoxRipemdData6.setBounds(new Rectangle(30, 187, 380, 20));
        jCheckBoxRipemdData6.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData7.setText("\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\"");
        jCheckBoxRipemdData7.setBounds(new Rectangle(30, 221, 445, 20));
        jCheckBoxRipemdData7.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData8.setText("8 times \"1234567890\"");
        jCheckBoxRipemdData8.setBounds(new Rectangle(30, 256, 255, 20));
        jCheckBoxRipemdData8.setFont(new Font("Dialog", 0, 10));
        jCheckBoxRipemdData9.setText("1 million a\'s");
        jCheckBoxRipemdData9.setBounds(new Rectangle(30, 290, 85, 20));
        jCheckBoxRipemdData9.setFont(new Font("Dialog", 0, 10));
        jCheckBoxSha32Data1.setText("\"abc\"");
        jCheckBoxSha32Data1.setBounds(new Rectangle(30, 15, 240, 20));
        jCheckBoxSha32Data1.setFont(new Font("Dialog", 0, 10));
        jCheckBoxSha32Data2.setText("\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"");
        jCheckBoxSha32Data2.setBounds(new Rectangle(30, 50, 340, 20));
        jCheckBoxSha32Data2.setFont(new Font("Dialog", 0, 10));
        jCheckBoxSha32Data3.setText("1 million a\'s");
        jCheckBoxSha32Data3.setBounds(new Rectangle(30, 84, 245, 20));
        jCheckBoxSha32Data3.setFont(new Font("Dialog", 0, 10));
        jCheckBoxSha64Data1.setText("\"abc\"");
        jCheckBoxSha64Data1.setBounds(new Rectangle(30, 15, 240, 20));
        jCheckBoxSha64Data1.setFont(new Font("Dialog", 0, 10));
        jCheckBoxSha64Data2.setBounds(new Rectangle(30, 50, 340, 20));
        jCheckBoxSha64Data2.setFont(new Font("Dialog", 0, 10));
        jCheckBoxSha64Data2.setText("\"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijkl");
        jCheckBoxSha64Data3.setText("1 million a\'s");
        jCheckBoxSha64Data3.setBounds(new Rectangle(30, 100, 245, 20));
        jCheckBoxSha64Data3.setFont(new Font("Dialog", 0, 10));
        jCheckBoxSha1.setText("Sha 1");
        jCheckBoxSha1.setBounds(new Rectangle(25, 35, 80, 20));
        jCheckBoxSha224.setText("Sha 224");
        jCheckBoxSha224.setBounds(new Rectangle(25, 70, 75, 20));
        jCheckBoxSha256.setText("Sha 256");
        jCheckBoxSha256.setBounds(new Rectangle(25, 109, 130, 20));
        jCheckBoxSha384.setText("Sha 384");
        jCheckBoxSha384.setBounds(new Rectangle(25, 146, 130, 20));
        jCheckBoxSha512.setText("Sha 512");
        jCheckBoxSha512.setBounds(new Rectangle(25, 183, 130, 20));
        jCheckBoxRipemd128.setText("Ripemd 128");
        jCheckBoxRipemd128.setBounds(new Rectangle(25, 219, 130, 20));
        jCheckBoxRipemd160.setText("Ripemd 160");
        jCheckBoxRipemd160.setBounds(new Rectangle(25, 256, 130, 20));
        jCheckBoxRipemd256.setText("Ripemd 256");
        jCheckBoxRipemd256.setBounds(new Rectangle(25, 293, 130, 20));
        jCheckBoxRipemd320.setText("Ripemd 320");
        jCheckBoxRipemd320.setBounds(new Rectangle(25, 330, 130, 20));
        jButtonHashSelectAll.setText("Select All");
        jButtonHashSelectAll.setBounds(new Rectangle(115, 40, 120, 20));
        jButtonHashSelectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonHashSelectAll_actionPerformed(e);
                }
            });
        jButtonHashDeselectAll.setText("Deselect All");
        jButtonHashDeselectAll.setBounds(new Rectangle(115, 75, 120, 20));
        jButtonHashDeselectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonHashDeselectAll_actionPerformed(e);
                }
            });
        jButtonRipemdSelectAll.setText("Select All");
        jButtonRipemdSelectAll.setBounds(new Rectangle(385, 25, 125, 20));
        jButtonRipemdSelectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonRipemdSelectAll_actionPerformed(e);
                }
            });
        jButtonRipemdDeselectAll.setText("Deselect All");
        jButtonRipemdDeselectAll.setBounds(new Rectangle(385, 65, 125, 20));
        jButtonRipemdDeselectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonRipemdDeselectAll_actionPerformed(e);
                }
            });
        jButtonSha32SelectAll.setText("Select All");
        jButtonSha32SelectAll.setBounds(new Rectangle(385, 25, 125, 20));
        jButtonSha32SelectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonSha32SelectAll_actionPerformed(e);
                }
            });
        jButtonSha32DeselectAll.setText("Deselect All");
        jButtonSha32DeselectAll.setBounds(new Rectangle(385, 65, 125, 20));
        jButtonSha32DeselectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonSha32DeselectAll_actionPerformed(e);
                }
            });
        jButtonSha64SelectAll.setText("Select All");
        jButtonSha64SelectAll.setBounds(new Rectangle(385, 25, 125, 20));
        jButtonSha64SelectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonSha64SelectAll_actionPerformed(e);
                }
            });
        jButtonSha64DeselectAll.setText("Deselect All");
        jButtonSha64DeselectAll.setBounds(new Rectangle(385, 65, 125, 20));
        jButtonSha64DeselectAll.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonSha64DeselectAll_actionPerformed(e);
                }
            });
        jLabelSha64DataLabel_2_1.setText("mnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu\"");
        jLabelSha64DataLabel_2_1.setBounds(new Rectangle(55, 75, 320, 15));
        jLabelSha64DataLabel_2_1.setFont(new Font("Dialog", 0, 10));
        jButtonReset.setText("Reset");
        jButtonReset.setBounds(new Rectangle(710, 422, 79, 21));
        jButtonReset.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonReset_actionPerformed(e);
                }
            });
        jButtonRunHashes.setText("Run Hashes");
        jButtonRunHashes.setBounds(new Rectangle(570, 422, 120, 20));
        jButtonRunHashes.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    jButtonRunHashes_actionPerformed(e);
                }
            });
        jProgressBarHashExecution.setBounds(new Rectangle(310, 422, 235, 20));
        menuFile.add( menuFileExit );
        menuBar.add( menuFile );
        menuHelp.add( menuHelpAbout );
        menuHelp.add(jMenuItemDiceLockWebSite);
        menuBar.add( menuHelp );
        this.getContentPane().add( statusBar, BorderLayout.SOUTH );
        jPanelSha32Data.add(jButtonSha32DeselectAll, null);
        jPanelSha32Data.add(jButtonSha32SelectAll, null);
        jPanelSha32Data.add(jCheckBoxSha32Data3, null);
        jPanelSha32Data.add(jCheckBoxSha32Data2, null);
        jPanelSha32Data.add(jCheckBoxSha32Data1, null);
        jTabbedPaneSelectInputData.addTab("Sha 1, Sha 224 & Sha 256", jPanelSha32Data);
        jTabbedPaneSelectInputData.addTab("Sha 384 & 512", jPanelSha64Data);
        jPanelSha64Data.add(jLabelSha64DataLabel_2_1, null);
        jPanelSha64Data.add(jButtonSha64DeselectAll, null);
        jPanelSha64Data.add(jButtonSha64SelectAll, null);
        jPanelSha64Data.add(jCheckBoxSha64Data3, null);
        jPanelSha64Data.add(jCheckBoxSha64Data2, null);
        jPanelSha64Data.add(jCheckBoxSha64Data1, null);
        jPanelRipemdData.add(jButtonRipemdDeselectAll, null);
        jPanelRipemdData.add(jButtonRipemdSelectAll, null);
        jPanelRipemdData.add(jCheckBoxRipemdData9, null);
        jPanelRipemdData.add(jCheckBoxRipemdData8, null);
        jPanelRipemdData.add(jCheckBoxRipemdData7, null);
        jPanelRipemdData.add(jCheckBoxRipemdData6, null);
        jPanelRipemdData.add(jCheckBoxRipemdData5, null);
        jPanelRipemdData.add(jCheckBoxRipemdData4, null);
        jPanelRipemdData.add(jCheckBoxRipemdData3, null);
        jPanelRipemdData.add(jCheckBoxRipemdData2, null);
        jPanelRipemdData.add(jCheckBoxRipemdData1, null);
        jTabbedPaneSelectInputData.addTab("Ripemd 128, 160, 256 & 320", jPanelRipemdData);
        jPanelSelectInputData.add(jTabbedPaneSelectInputData, null);
        panelCenter.add(jProgressBarHashExecution, null);
        panelCenter.add(jButtonRunHashes, null);
        panelCenter.add(jButtonReset, null);
        panelCenter.add(jPanelSelectInputData, null);
        panelCenter.add(jButtonClose, null);
        jPanelSelectHashes.add(jButtonHashDeselectAll, null);
        jPanelSelectHashes.add(jButtonHashSelectAll, null);
        jPanelSelectHashes.add(jCheckBoxRipemd320, null);
        jPanelSelectHashes.add(jCheckBoxRipemd256, null);
        jPanelSelectHashes.add(jCheckBoxRipemd160, null);
        jPanelSelectHashes.add(jCheckBoxRipemd128, null);
        jPanelSelectHashes.add(jCheckBoxSha512, null);
        jPanelSelectHashes.add(jCheckBoxSha384, null);
        jPanelSelectHashes.add(jCheckBoxSha256, null);
        jPanelSelectHashes.add(jCheckBoxSha224, null);
        jPanelSelectHashes.add(jCheckBoxSha1, null);
        panelCenter.add(jPanelSelectHashes, null);
        this.getContentPane().add(panelCenter, BorderLayout.CENTER);
        this.setIconImage(imageDiceLock);
        this.setTitle("DiceLock Security - JDigesterCheck 5.0.0.1");
        this.setResizable(false);
        createFixedData();
        createInputDataStreams();
        loadExpectedValues();
        createHashAlgorithms();
    }

    void fileExit_ActionPerformed(ActionEvent e) {
        System.exit(0);
    }

    void helpAbout_ActionPerformed(ActionEvent e) {
        JOptionPane.showMessageDialog(this, new JDigesterCheckFrame_AboutBoxPanel1(), "About", JOptionPane.PLAIN_MESSAGE);
    }

    private void jMenuItemDiceLockWebSite_actionPerformed(ActionEvent e) throws URISyntaxException, IOException {
        URI uri;
        try {
            uri = new URI("http://www.dicelocksecurity.com/");
        } catch (URISyntaxException f) {
            throw f;
        }
        Desktop desktop = Desktop.getDesktop();
        try {
            desktop.browse(uri);
        } catch (IOException f) {
            throw f;
        }
    }

    private void jButtonClose_actionPerformed(ActionEvent e) {
        System.exit(0);
    }

    private void createFixedData() {
        // Hash algorithms
        hashAlgorithms[0] = "SHA 1";
        hashAlgorithms[1] = "SHA 224";
        hashAlgorithms[2] = "SHA 256";
        hashAlgorithms[3] = "SHA 384";
        hashAlgorithms[4] = "SHA 512";
        hashAlgorithms[5] = "RIPEMD 128";
        hashAlgorithms[6] = "RIPEMD 160";
        hashAlgorithms[7] = "RIPEMD 256";
        hashAlgorithms[8] = "RIPEMD 320";
    }

    private void createInputDataStreams() {
        // Sha 32
        data_sha_32[0] = new DefaultCryptoRandomStream();
        data_sha_32[0].SetCryptoRandomStreamUC("abc".getBytes(), 3);
        label_sha_32[0] = "abc";
        data_sha_32[1] = new DefaultCryptoRandomStream();
        data_sha_32[1].SetCryptoRandomStreamUC("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(), 56);
        label_sha_32[1] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        data_sha_32[2] = new DefaultCryptoRandomStream();
        data_sha_32[2].SetCryptoRandomStreamUC(1000000);
        data_sha_32[2].FillUC((byte)'a');
        label_sha_32[2] = "1 million a's";
        // Sha 64
        data_sha_64[0] = new DefaultCryptoRandomStream();
        data_sha_64[0].SetCryptoRandomStreamUC("abc".getBytes(), 3);
        label_sha_64[0] = "abc";
        data_sha_64[1] = new DefaultCryptoRandomStream();
        data_sha_64[1].SetCryptoRandomStreamUC("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".getBytes(), 112);
        label_sha_64[1] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        data_sha_64[2] = new DefaultCryptoRandomStream();
        data_sha_64[2].SetCryptoRandomStreamUC(1000000);
        data_sha_64[2].FillUC((byte)'a');
        label_sha_64[2] = "1 million a's";
        // Ripemd
        data_ripemd[0] = new DefaultCryptoRandomStream();
        label_ripemd[0] = "empty string \"\"";
        data_ripemd[1] = new DefaultCryptoRandomStream();
        data_ripemd[1].SetCryptoRandomStreamUC("a".getBytes(), 1);
        label_ripemd[1] = "a";
        data_ripemd[2] = new DefaultCryptoRandomStream();
        data_ripemd[2].SetCryptoRandomStreamUC("abc".getBytes(), 3);
        label_ripemd[2] = "abc";
        data_ripemd[3] = new DefaultCryptoRandomStream();
        data_ripemd[3].SetCryptoRandomStreamUC("message digest".getBytes(), 14);
        label_ripemd[3] = "message digest";
        data_ripemd[4] = new DefaultCryptoRandomStream();
        data_ripemd[4].SetCryptoRandomStreamUC("abcdefghijklmnopqrstuvwxyz".getBytes(), 26);
        label_ripemd[4] = "abcdefghijklmnopqrstuvwxyz";
        data_ripemd[5] = new DefaultCryptoRandomStream();
        data_ripemd[5].SetCryptoRandomStreamUC("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(), 56);
        label_ripemd[5] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        data_ripemd[6] = new DefaultCryptoRandomStream();
        data_ripemd[6].SetCryptoRandomStreamUC("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes(), 62);
        label_ripemd[6] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        data_ripemd[7] = new DefaultCryptoRandomStream();
        data_ripemd[7].SetCryptoRandomStreamUC("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes(), 80);
        label_ripemd[7] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        data_ripemd[8] = new DefaultCryptoRandomStream();
        data_ripemd[8].SetCryptoRandomStreamUC(1000000);
        data_ripemd[8].FillUC((byte)'a');
        label_ripemd[8] = "1 million a's";
        
    }

    private void loadExpectedValues() {
        expected_sha_1[0] = "a9993e364706816aba3e25717850c26c9cd0d89d";
        expected_sha_1[1] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
        expected_sha_1[2] = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
        expected_sha_224[0] = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
        expected_sha_224[1] = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";
        expected_sha_224[2] = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";
        expected_sha_256[0] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        expected_sha_256[1] = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        expected_sha_256[2] = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        expected_sha_384[0] = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
        expected_sha_384[1] = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039";
        expected_sha_384[2] = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985";
        expected_sha_512[0] = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        expected_sha_512[1] = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
        expected_sha_512[2] = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
        expected_ripemd_128[0] = "cdf26213a150dc3ecb610f18f6b38b46";
        expected_ripemd_128[1] = "86be7afa339d0fc7cfc785e72f578d33";
        expected_ripemd_128[2] = "c14a12199c66e4ba84636b0f69144c77";
        expected_ripemd_128[3] = "9e327b3d6e523062afc1132d7df9d1b8";
        expected_ripemd_128[4] = "fd2aa607f71dc8f510714922b371834e";
        expected_ripemd_128[5] = "a1aa0689d0fafa2ddc22e88b49133a06";
        expected_ripemd_128[6] = "d1e959eb179c911faea4624c60c5c702";
        expected_ripemd_128[7] = "3f45ef194732c2dbb2c4a2c769795fa3";
        expected_ripemd_128[8] = "4a7f5723f954eba1216c9d8f6320431f";
        expected_ripemd_160[0] = "9c1185a5c5e9fc54612808977ee8f548b2258d31";
        expected_ripemd_160[1] = "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe";
        expected_ripemd_160[2] = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
        expected_ripemd_160[3] = "5d0689ef49d2fae572b881b123a85ffa21595f36";
        expected_ripemd_160[4] = "f71c27109c692c1b56bbdceb5b9d2865b3708dbc";
        expected_ripemd_160[5] = "12a053384a9c0c88e405a06c27dcf49ada62eb2b";
        expected_ripemd_160[6] = "b0e20b6e3116640286ed3a87a5713079b21f5189";
        expected_ripemd_160[7] = "9b752e45573d4b39f4dbd3323cab82bf63326bfb";
        expected_ripemd_160[8] = "52783243c1697bdbe16d37f97f68f08325dc1528";
        expected_ripemd_256[0] = "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d";
        expected_ripemd_256[1] = "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925";
        expected_ripemd_256[2] = "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65";
        expected_ripemd_256[3] = "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e";
        expected_ripemd_256[4] = "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133";
        expected_ripemd_256[5] = "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f";
        expected_ripemd_256[6] = "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8";
        expected_ripemd_256[7] = "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd";
        expected_ripemd_256[8] = "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978";
        expected_ripemd_320[0] = "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8";
        expected_ripemd_320[1] = "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d";
        expected_ripemd_320[2] = "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d";
        expected_ripemd_320[3] = "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197";
        expected_ripemd_320[4] = "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009";
        expected_ripemd_320[5] = "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac";
        expected_ripemd_320[6] = "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4";
        expected_ripemd_320[7] = "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42";
        expected_ripemd_320[8] = "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66";
    }

    private void createHashAlgorithms() {
        hashSuite.AddAll();
        digestSha1 = new DefaultCryptoRandomStream(hashSuite.GetSha1().GetBitHashLength());
        hashSuite.GetSha1().SetMessageDigest(digestSha1);
        digestSha224 = new DefaultCryptoRandomStream(hashSuite.GetSha224().GetBitHashLength());
        hashSuite.GetSha224().SetMessageDigest(digestSha224);
        digestSha256 = new DefaultCryptoRandomStream(hashSuite.GetSha256().GetBitHashLength());
        hashSuite.GetSha256().SetMessageDigest(digestSha256);
        digestSha384 = new DefaultCryptoRandomStream(hashSuite.GetSha384().GetBitHashLength());
        hashSuite.GetSha384().SetMessageDigest(digestSha384);
        digestSha512 = new DefaultCryptoRandomStream(hashSuite.GetSha512().GetBitHashLength());
        hashSuite.GetSha512().SetMessageDigest(digestSha512);
        digestRipemd128 = new DefaultCryptoRandomStream(hashSuite.GetRipemd128().GetBitHashLength());
        hashSuite.GetRipemd128().SetMessageDigest(digestRipemd128);
        digestRipemd160 = new DefaultCryptoRandomStream(hashSuite.GetRipemd160().GetBitHashLength());
        hashSuite.GetRipemd160().SetMessageDigest(digestRipemd160);
        digestRipemd256 = new DefaultCryptoRandomStream(hashSuite.GetRipemd256().GetBitHashLength());
        hashSuite.GetRipemd256().SetMessageDigest(digestRipemd256);
        digestRipemd320 = new DefaultCryptoRandomStream(hashSuite.GetRipemd320().GetBitHashLength());
        hashSuite.GetRipemd320().SetMessageDigest(digestRipemd320);
    }

    private void executeSha1() {
        if ( this.jCheckBoxSha32Data1.isSelected() ) {
            hashSuite.GetSha1().Initialize();
            hashSuite.GetSha1().Add(data_sha_32[0]);
            hashSuite.GetSha1().Finalize();
            dialogResults.AddResult(hashAlgorithms[0], label_sha_32[0], expected_sha_1[0], hashSuite.GetSha1().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha32Data2.isSelected() ) {
            hashSuite.GetSha1().Initialize();
            hashSuite.GetSha1().Add(data_sha_32[1]);
            hashSuite.GetSha1().Finalize();
            dialogResults.AddResult(hashAlgorithms[0], label_sha_32[1], expected_sha_1[1], hashSuite.GetSha1().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha32Data3.isSelected() ) {
            hashSuite.GetSha1().Initialize();
            hashSuite.GetSha1().Add(data_sha_32[2]);
            hashSuite.GetSha1().Finalize();
            dialogResults.AddResult(hashAlgorithms[0], label_sha_32[2], expected_sha_1[2], hashSuite.GetSha1().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeSha224() {
        if ( this.jCheckBoxSha32Data1.isSelected() ) {
            hashSuite.GetSha224().Initialize();
            hashSuite.GetSha224().Add(data_sha_32[0]);
            hashSuite.GetSha224().Finalize();
            dialogResults.AddResult(hashAlgorithms[1], label_sha_32[0], expected_sha_224[0], hashSuite.GetSha224().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha32Data2.isSelected() ) {
            hashSuite.GetSha224().Initialize();
            hashSuite.GetSha224().Add(data_sha_32[1]);
            hashSuite.GetSha224().Finalize();
            dialogResults.AddResult(hashAlgorithms[1], label_sha_32[1], expected_sha_224[1], hashSuite.GetSha224().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha32Data3.isSelected() ) {
            hashSuite.GetSha224().Initialize();
            hashSuite.GetSha224().Add(data_sha_32[2]);
            hashSuite.GetSha224().Finalize();
            dialogResults.AddResult(hashAlgorithms[1], label_sha_32[2], expected_sha_224[2], hashSuite.GetSha224().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeSha256() {
        if ( this.jCheckBoxSha32Data1.isSelected() ) {
            hashSuite.GetSha256().Initialize();
            hashSuite.GetSha256().Add(data_sha_32[0]);
            hashSuite.GetSha256().Finalize();
            dialogResults.AddResult(hashAlgorithms[2], label_sha_32[0], expected_sha_256[0], hashSuite.GetSha256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha32Data2.isSelected() ) {
            hashSuite.GetSha256().Initialize();
            hashSuite.GetSha256().Add(data_sha_32[1]);
            hashSuite.GetSha256().Finalize();
            dialogResults.AddResult(hashAlgorithms[2], label_sha_32[1], expected_sha_256[1], hashSuite.GetSha256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha32Data3.isSelected() ) {
            hashSuite.GetSha256().Initialize();
            hashSuite.GetSha256().Add(data_sha_32[2]);
            hashSuite.GetSha256().Finalize();
            dialogResults.AddResult(hashAlgorithms[2], label_sha_32[2], expected_sha_256[2], hashSuite.GetSha256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeSha384() {
        if ( this.jCheckBoxSha64Data1.isSelected() ) {
            hashSuite.GetSha384().Initialize();
            hashSuite.GetSha384().Add(data_sha_64[0]);
            hashSuite.GetSha384().Finalize();
            dialogResults.AddResult(hashAlgorithms[3], label_sha_64[0], expected_sha_384[0], hashSuite.GetSha384().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha64Data2.isSelected() ) {
            hashSuite.GetSha384().Initialize();
            hashSuite.GetSha384().Add(data_sha_64[1]);
            hashSuite.GetSha384().Finalize();
            dialogResults.AddResult(hashAlgorithms[3], label_sha_64[1], expected_sha_384[1], hashSuite.GetSha384().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha64Data3.isSelected() ) {
            hashSuite.GetSha384().Initialize();
            hashSuite.GetSha384().Add(data_sha_64[2]);
            hashSuite.GetSha384().Finalize();
            dialogResults.AddResult(hashAlgorithms[3], label_sha_64[2], expected_sha_384[2], hashSuite.GetSha384().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeSha512() {
        if ( this.jCheckBoxSha64Data1.isSelected() ) {
            hashSuite.GetSha512().Initialize();
            hashSuite.GetSha512().Add(data_sha_64[0]);
            hashSuite.GetSha512().Finalize();
            dialogResults.AddResult(hashAlgorithms[4], label_sha_64[0], expected_sha_512[0], hashSuite.GetSha512().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha64Data2.isSelected() ) {
            hashSuite.GetSha512().Initialize();
            hashSuite.GetSha512().Add(data_sha_64[1]);
            hashSuite.GetSha512().Finalize();
            dialogResults.AddResult(hashAlgorithms[4], label_sha_64[1], expected_sha_512[1], hashSuite.GetSha512().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxSha64Data3.isSelected() ) {
            hashSuite.GetSha512().Initialize();
            hashSuite.GetSha512().Add(data_sha_64[2]);
            hashSuite.GetSha512().Finalize();
            dialogResults.AddResult(hashAlgorithms[4], label_sha_64[2], expected_sha_512[2], hashSuite.GetSha512().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeRipemd128() {
        if ( this.jCheckBoxRipemdData1.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[0]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[0], expected_ripemd_128[0], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData2.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[1]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[1], expected_ripemd_128[1], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData3.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[2]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[2], expected_ripemd_128[2], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData4.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[3]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[3], expected_ripemd_128[3], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData5.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[4]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[4], expected_ripemd_128[4], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData6.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[5]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[5], expected_ripemd_128[5], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData7.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[6]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[6], expected_ripemd_128[6], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData8.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[7]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[7], expected_ripemd_128[7], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData9.isSelected() ) {
            hashSuite.GetRipemd128().Initialize();
            hashSuite.GetRipemd128().Add(data_ripemd[8]);
            hashSuite.GetRipemd128().Finalize();
            dialogResults.AddResult(hashAlgorithms[5], label_ripemd[8], expected_ripemd_128[8], hashSuite.GetRipemd128().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeRipemd160() {
        if ( this.jCheckBoxRipemdData1.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[0]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[0], expected_ripemd_160[0], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData2.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[1]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[1], expected_ripemd_160[1], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData3.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[2]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[2], expected_ripemd_160[2], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData4.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[3]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[3], expected_ripemd_160[3], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData5.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[4]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[4], expected_ripemd_160[4], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData6.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[5]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[5], expected_ripemd_160[5], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData7.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[6]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[6], expected_ripemd_160[6], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData8.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[7]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[7], expected_ripemd_160[7], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData9.isSelected() ) {
            hashSuite.GetRipemd160().Initialize();
            hashSuite.GetRipemd160().Add(data_ripemd[8]);
            hashSuite.GetRipemd160().Finalize();
            dialogResults.AddResult(hashAlgorithms[6], label_ripemd[8], expected_ripemd_160[8], hashSuite.GetRipemd160().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeRipemd256() {
        if ( this.jCheckBoxRipemdData1.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[0]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[0], expected_ripemd_256[0], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData2.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[1]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[1], expected_ripemd_256[1], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData3.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[2]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[2], expected_ripemd_256[2], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData4.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[3]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[3], expected_ripemd_256[3], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData5.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[4]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[4], expected_ripemd_256[4], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData6.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[5]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[5], expected_ripemd_256[5], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData7.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[6]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[6], expected_ripemd_256[6], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData8.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[7]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[7], expected_ripemd_256[7], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData9.isSelected() ) {
            hashSuite.GetRipemd256().Initialize();
            hashSuite.GetRipemd256().Add(data_ripemd[8]);
            hashSuite.GetRipemd256().Finalize();
            dialogResults.AddResult(hashAlgorithms[7], label_ripemd[8], expected_ripemd_256[8], hashSuite.GetRipemd256().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }

    private void executeRipemd320() {
        if ( this.jCheckBoxRipemdData1.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[0]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[0], expected_ripemd_320[0], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData2.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[1]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[1], expected_ripemd_320[1], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData3.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[2]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[2], expected_ripemd_320[2], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData4.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[3]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[3], expected_ripemd_320[3], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData5.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[4]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[4], expected_ripemd_320[4], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData6.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[5]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[5], expected_ripemd_320[5], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData7.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[6]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[6], expected_ripemd_320[6], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData8.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[7]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[7], expected_ripemd_320[7], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
        if ( this.jCheckBoxRipemdData9.isSelected() ) {
            hashSuite.GetRipemd320().Initialize();
            hashSuite.GetRipemd320().Add(data_ripemd[8]);
            hashSuite.GetRipemd320().Finalize();
            dialogResults.AddResult(hashAlgorithms[8], label_ripemd[8], expected_ripemd_320[8], hashSuite.GetRipemd320().GetMessageDigest());
            jProgressBarHashExecution.setValue(jProgressBarHashExecution.getValue() + 1);
        }
    }


    private short computeProgressBar() {
        short computeTotal, computeSha32, computeSha64, computeRipemd;
        
        computeTotal = 0;
        computeSha32 = 0;
        computeSha64 = 0;
        computeRipemd = 0;
        if ( this.jCheckBoxSha32Data1.isSelected() ) computeSha32++;
        if ( this.jCheckBoxSha32Data2.isSelected() ) computeSha32++;
        if ( this.jCheckBoxSha32Data3.isSelected() ) computeSha32++;

        if ( this.jCheckBoxSha64Data1.isSelected() ) computeSha64++;
        if ( this.jCheckBoxSha64Data2.isSelected() ) computeSha64++;
        if ( this.jCheckBoxSha64Data3.isSelected() ) computeSha64++;
        
        if ( this.jCheckBoxRipemdData1.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData2.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData3.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData4.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData5.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData6.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData7.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData8.isSelected() ) computeRipemd++;
        if ( this.jCheckBoxRipemdData9.isSelected() ) computeRipemd++;

        if ( this.jCheckBoxSha1.isSelected() ) computeTotal += computeSha32;
        if ( this.jCheckBoxSha224.isSelected() ) computeTotal += computeSha32;
        if ( this.jCheckBoxSha256.isSelected() ) computeTotal += computeSha32;
        if ( this.jCheckBoxSha384.isSelected() ) computeTotal += computeSha64;
        if ( this.jCheckBoxSha512.isSelected() ) computeTotal += computeSha64;
        if ( this.jCheckBoxRipemd128.isSelected() ) computeTotal += computeRipemd;
        if ( this.jCheckBoxRipemd160.isSelected() ) computeTotal += computeRipemd;
        if ( this.jCheckBoxRipemd256.isSelected() ) computeTotal += computeRipemd;
        if ( this.jCheckBoxRipemd320.isSelected() ) computeTotal += computeRipemd;
//        currentHashExecution = 0;
        return computeTotal;
    }

    
    private void executeHashAlgorithms() {
        // Result dialog reset
        dialogResults.resetDialog();
        // Compute hashes
        if ( this.jCheckBoxSha1.isSelected() ) {
            executeSha1();
        }
        if ( this.jCheckBoxSha224.isSelected() ) {
            executeSha224();
        }
        if ( this.jCheckBoxSha256.isSelected() ) {
            executeSha256();
        }
        if ( this.jCheckBoxSha384.isSelected() ) {
            executeSha384();
        }
        if ( this.jCheckBoxSha512.isSelected() ) {
            executeSha512();
        }
        if ( this.jCheckBoxRipemd128.isSelected() ) {
            executeRipemd128();
        }
        if ( this.jCheckBoxRipemd160.isSelected() ) {
            executeRipemd160();
        }
        if ( this.jCheckBoxRipemd256.isSelected() ) {
            executeRipemd256();
        }
        if ( this.jCheckBoxRipemd320.isSelected() ) {
            executeRipemd320();
        }
    }

    private void jButtonHashSelectAll_actionPerformed(ActionEvent e) {
        jCheckBoxSha1.setSelected(true);
        jCheckBoxSha224.setSelected(true);
        jCheckBoxSha256.setSelected(true);
        jCheckBoxSha384.setSelected(true);
        jCheckBoxSha512.setSelected(true);
        jCheckBoxRipemd128.setSelected(true);
        jCheckBoxRipemd160.setSelected(true);
        jCheckBoxRipemd256.setSelected(true);
        jCheckBoxRipemd320.setSelected(true);
    }

    private void jButtonHashDeselectAll_actionPerformed(ActionEvent e) {
        jCheckBoxSha1.setSelected(false);
        jCheckBoxSha224.setSelected(false);
        jCheckBoxSha256.setSelected(false);
        jCheckBoxSha384.setSelected(false);
        jCheckBoxSha512.setSelected(false);
        jCheckBoxRipemd128.setSelected(false);
        jCheckBoxRipemd160.setSelected(false);
        jCheckBoxRipemd256.setSelected(false);
        jCheckBoxRipemd320.setSelected(false);
    }

    private void jButtonSha32SelectAll_actionPerformed(ActionEvent e) {
        jCheckBoxSha32Data1.setSelected(true);
        jCheckBoxSha32Data2.setSelected(true);
        jCheckBoxSha32Data3.setSelected(true);
    }

    private void jButtonSha32DeselectAll_actionPerformed(ActionEvent e) {
        jCheckBoxSha32Data1.setSelected(false);
        jCheckBoxSha32Data2.setSelected(false);
        jCheckBoxSha32Data3.setSelected(false);
    }

    private void jButtonSha64SelectAll_actionPerformed(ActionEvent e) {
        jCheckBoxSha64Data1.setSelected(true);
        jCheckBoxSha64Data2.setSelected(true);
        jCheckBoxSha64Data3.setSelected(true);
    }

    private void jButtonSha64DeselectAll_actionPerformed(ActionEvent e) {
        jCheckBoxSha64Data1.setSelected(false);
        jCheckBoxSha64Data2.setSelected(false);
        jCheckBoxSha64Data3.setSelected(false);
    }

    private void jButtonRipemdSelectAll_actionPerformed(ActionEvent e) {
        jCheckBoxRipemdData1.setSelected(true);
        jCheckBoxRipemdData2.setSelected(true);
        jCheckBoxRipemdData3.setSelected(true);
        jCheckBoxRipemdData4.setSelected(true);
        jCheckBoxRipemdData5.setSelected(true);
        jCheckBoxRipemdData6.setSelected(true);
        jCheckBoxRipemdData7.setSelected(true);
        jCheckBoxRipemdData8.setSelected(true);
        jCheckBoxRipemdData9.setSelected(true);
    }

    private void jButtonRipemdDeselectAll_actionPerformed(ActionEvent e) {
        jCheckBoxRipemdData1.setSelected(false);
        jCheckBoxRipemdData2.setSelected(false);
        jCheckBoxRipemdData3.setSelected(false);
        jCheckBoxRipemdData4.setSelected(false);
        jCheckBoxRipemdData5.setSelected(false);
        jCheckBoxRipemdData6.setSelected(false);
        jCheckBoxRipemdData7.setSelected(false);
        jCheckBoxRipemdData8.setSelected(false);
        jCheckBoxRipemdData9.setSelected(false);
    }

    private void jButtonReset_actionPerformed(ActionEvent e) {
        // Hashes
        jCheckBoxSha1.setSelected(false);
        jCheckBoxSha224.setSelected(false);
        jCheckBoxSha256.setSelected(false);
        jCheckBoxSha384.setSelected(false);
        jCheckBoxSha512.setSelected(false);
        jCheckBoxRipemd128.setSelected(false);
        jCheckBoxRipemd160.setSelected(false);
        jCheckBoxRipemd256.setSelected(false);
        jCheckBoxRipemd320.setSelected(false);
        // Sha 32 data reset
        jCheckBoxSha32Data1.setSelected(false);
        jCheckBoxSha32Data2.setSelected(false);
        jCheckBoxSha32Data3.setSelected(false);
        // Sha 64 data reset
        jCheckBoxSha64Data1.setSelected(false);
        jCheckBoxSha64Data2.setSelected(false);
        jCheckBoxSha64Data3.setSelected(false);
        // Sha Ripemd data reset
        jCheckBoxRipemdData1.setSelected(false);
        jCheckBoxRipemdData2.setSelected(false);
        jCheckBoxRipemdData3.setSelected(false);
        jCheckBoxRipemdData4.setSelected(false);
        jCheckBoxRipemdData5.setSelected(false);
        jCheckBoxRipemdData6.setSelected(false);
        jCheckBoxRipemdData7.setSelected(false);
        jCheckBoxRipemdData8.setSelected(false);
        jCheckBoxRipemdData9.setSelected(false);
        // Result dialog reset
        dialogResults.resetDialog();
        jProgressBarHashExecution.setMinimum(0);
        jProgressBarHashExecution.setMaximum(0);
    }

    private void jButtonRunHashes_actionPerformed(ActionEvent e) {

        jProgressBarHashExecution.setMinimum(0);
        jProgressBarHashExecution.setMaximum(computeProgressBar());
        jProgressBarHashExecution.setStringPainted(true);
        Runnable runExecution = new Runnable() {
           public void run() {
              try {
                  executeHashAlgorithms();
                  dialogResults.setVisible(true);
                  jProgressBarHashExecution.setStringPainted(false);
                  jProgressBarHashExecution.setValue(0);
              }
              catch (Exception e) {
                 e.printStackTrace();
              }
           }
        };
        Thread thread;
        thread = new Thread(runExecution);
        thread.start();
    }
}
