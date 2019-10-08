package krypton.server;
import java.awt.Color;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.swing.JFileChooser;
import org.apache.commons.codec.binary.Base64;
public class KryptonMainServer extends javax.swing.JFrame {
    public Cipher cipher;
    public String url ="jdbc:mysql://localhost/krypton";
    public String user="phpmyadmin";
    public String pass="some_pass";
         
    public KryptonMainServer() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException  {
        initComponents();
        this.cipher=Cipher.getInstance("RSA");       
    }
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        createbutton = new javax.swing.JButton();
        startbutton = new javax.swing.JButton();
        statuslabel = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Main Server");

        createbutton.setText("Create Key");
        createbutton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                createbuttonActionPerformed(evt);
            }
        });

        startbutton.setText("Start");
        startbutton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                startbuttonActionPerformed(evt);
            }
        });

        jLabel1.setText("Generate keys for the server......");

        jLabel2.setText("Start the Server to listen for requests.");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 276, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(108, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(61, 61, 61)
                        .addComponent(startbutton, javax.swing.GroupLayout.PREFERRED_SIZE, 80, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(59, 59, 59)
                        .addComponent(createbutton)))
                .addGap(0, 0, Short.MAX_VALUE))
            .addComponent(statuslabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(40, Short.MAX_VALUE)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(createbutton)
                .addGap(28, 28, 28)
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 17, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(startbutton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(statuslabel, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void startbuttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_startbuttonActionPerformed
        try {   statuslabel.setText("Server started ......");
                statuslabel.setForeground(Color.green);
            listener();           
        } catch (Exception ex) {
            statuslabel.setText(ex.getMessage());
        }
    }//GEN-LAST:event_startbuttonActionPerformed
    private void createbuttonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_createbuttonActionPerformed
            JFileChooser chooser=new JFileChooser();
            chooser.setDialogTitle("Where do you wish to save the key"); 
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.showSaveDialog(null);
            PrivateKey privkey;PublicKey pubkey; 
            try {            
            KeyPairGenerator keygen=KeyPairGenerator.getInstance("RSA");
            keygen.initialize(1024);
            KeyPair pair=keygen.generateKeyPair();
            privkey =pair.getPrivate();
            pubkey=pair.getPublic();
            String keypath=chooser.getSelectedFile().getAbsolutePath();
            writefile(privkey.getEncoded(),keypath+"/server.private.key");
            writefile(pubkey.getEncoded(),keypath+"/server.public.key");
            } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }//GEN-LAST:event_createbuttonActionPerformed
    public static void writefile(byte[] data,String filename) throws FileNotFoundException, IOException{
        File outfile= new File(filename);
        FileOutputStream outdata=new FileOutputStream(outfile);
        outdata.write(data);
        outdata.close();
    }
    public static void writelogs(String data,String filename) throws FileNotFoundException, IOException{
        File outfile= new File(filename);
        FileWriter outdata=new FileWriter(outfile,true);
        outdata.write(data);
        outdata.close();
    }
    public PrivateKey getPrivate(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException{
      byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);  
    }
    public String decryptText(String msg, PrivateKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return  new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8"); 
	} 
    public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}   
    public String encryptText(String msg, PublicKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException  {    this.cipher.init(Cipher.ENCRYPT_MODE , key);		
                return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}
    public void listener() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        socket1 s1=new socket1();
        Socket2 s2=new Socket2();
        Thread t1=new Thread(s1);
        Thread t2=new Thread(s2);
        t1.start();
        t2.start();       
              
    }
  
    public static void main(String args[]) {
      try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(KryptonMainServer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(KryptonMainServer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(KryptonMainServer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(KryptonMainServer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
   
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    new KryptonMainServer().setVisible(true);
                } catch (Exception ex) {
                    Logger.getLogger(KryptonMainServer.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton createbutton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JButton startbutton;
    private javax.swing.JLabel statuslabel;
    // End of variables declaration//GEN-END:variables
}
class socket1 implements Runnable {

    
    @Override
    public void run() {
        //System.setProperty("javax.net.ssl.keyStore", "/home/x/mykeystore/examplestore");
        //System.setProperty("javax.net.ssl.keyStorePassword", "paulmbugua");
        //SSLServerSocketFactory sf=(SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        while(true){  
       try
        {  
       
                 ServerSocket ss =new ServerSocket(4444);         
           // Socket s =ss.accept();
            //ServerSocket ss=sf.createServerSocket(4444);
            Socket s=ss.accept();
                DataInputStream dis = new DataInputStream(s.getInputStream()); 
                DataOutputStream dos = new DataOutputStream(s.getOutputStream()); 
            String input = (String)dis.readUTF();
                
        String filenameout="/home/x/Krypton/server.private.key"; 
        KryptonMainServer ks =new KryptonMainServer();        
        PrivateKey serverpriv=ks.getPrivate(filenameout);    
        String result=ks.decryptText(input, serverpriv); 
        
        String password=result.substring(0,result.indexOf("-"));
        String email =result.substring(result.indexOf("-")+1,result.length());
        MessageDigest md=MessageDigest.getInstance("SHA-512");
        byte[] mesdg=md.digest(password.getBytes());
            BigInteger no = new BigInteger(1,mesdg);
                String hashtext = no.toString(16); 
                    while (hashtext.length() < 32) { 
                        hashtext = "0" + hashtext; 
                    } 
                    
        Class.forName("com.mysql.cj.jdbc.Driver");
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost/krypton", "phpmyadmin", "some_pass");
        String query="select publickey from Users where Email=? and password=? ";
        PreparedStatement pstmt=con.prepareStatement(query);
        pstmt.setString(1, email);
        pstmt.setString(2,hashtext);
        ResultSet rs=pstmt.executeQuery();       
            String x="";
            String res="";
       if(!rs.next())
       {           
          String log="wrong attempt by email: "+ email;
          ks.writelogs(log, "/home/x/Krypton/logs.txt");
          dos.writeUTF("false");
           
       }
       else{
            String log="Successful attempt by email: "+email;
            ks.writelogs(log, "/home/x/Krypton/logs.txt");
            PublicKey pk=ks.getPublic(rs.getString(1));
            x="true";res = ks.encryptText(x,pk);
            dos.writeUTF(res);
       }
      
         s.close();
         ss.close();
            }
        
        catch(Exception e)
        { 
            System.out.println(e.getMessage());
        }
       }
    }
    
}
class Socket2 implements Runnable {

    @Override
    public void run() {
          //System.setProperty("javax.net.ssl.keyStore", "/home/x/mykeystore/examplestore");
       // System.setProperty("javax.net.ssl.keyStorePassword", "paulmbugua");
     // SSLServerSocketFactory sf=(SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
      while(true){  
      try{
            KryptonMainServer ks1 =new KryptonMainServer();
           // ServerSocket ss1=sf.createServerSocket(4445);
           // Socket s1=ss1.accept();
            ServerSocket ss1 =new ServerSocket(4445);    
           Socket s1=ss1.accept();
            DataInputStream dis1 = new DataInputStream(s1.getInputStream());
            DataOutputStream dos1 = new DataOutputStream(s1.getOutputStream());
            String emailz=dis1.readUTF();
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection con1= DriverManager.getConnection("jdbc:mysql://localhost/krypton", "phpmyadmin", "some_pass");
            String query1="select publickey from Users where Email=?";
            PreparedStatement pstmt1=con1.prepareStatement(query1);
            pstmt1.setString(1, emailz);
            ResultSet rs1=pstmt1.executeQuery();
       if(!rs1.next())
       {    String log="Request for the publickey of email  "+emailz+"failed ";
            ks1.writelogs(log, "/home/x/Krypton/logs.txt");
            File myfile= new File("/home/x/Krypton/blank");
            byte[] mb =new byte[(int) myfile.length()];
            BufferedInputStream bis =new BufferedInputStream(new FileInputStream(myfile));
            bis.read(mb,0,mb.length);
            OutputStream os=s1.getOutputStream();
            os.write(mb,0,mb.length);
            os.flush();
           
       }
       else{String log="Request for the publickey of email "+emailz+"successful ";
            ks1.writelogs(log, "/home/x/Krypton/logs.txt");
           
            File myfile= new File(rs1.getString(1));
            byte[] mb =new byte[(int) myfile.length()];
            BufferedInputStream bis =new BufferedInputStream(new FileInputStream(myfile));
            bis.read(mb,0,mb.length);
            OutputStream os=s1.getOutputStream();
            os.write(mb,0,mb.length);
            os.flush();
             
       }
      
         s1.close();
         ss1.close();
        
       }catch(Exception e){
       System.out.println(e.getMessage());
       }}
    }
}
