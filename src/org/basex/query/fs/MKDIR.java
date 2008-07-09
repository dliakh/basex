package org.basex.query.fs;

import static org.basex.query.fs.FSText.*;
import java.io.IOException;
import org.basex.core.Context;
import org.basex.io.PrintOutput;
import org.basex.util.GetOpts;
import org.basex.util.Token;

/**
 * Performs a touch command.
 * 
 * @author Workgroup DBIS, University of Konstanz 2005-08, ISC License
 * @author Hannes Schwarz - Hannes.Schwarz@gmail.com
 *
 */
public class MKDIR {

  /** Data reference. */
  private final Context context;

  /** current dir. */
  private int curDirPre;

  /** PrintOutPutStream. */
  private PrintOutput out;


  /**
   * Simplified Constructor.
   * @param ctx data context
   * @param output output stream
   */
  public MKDIR(final Context ctx, final PrintOutput output) {
    this.context = ctx;
    curDirPre = ctx.current().pre[0];
    this.out = output;
  }

  /**
   * Performs a touch command.
   * 
   * @param cmd - command line
   * @throws IOException - in case of problems with the PrintOutput 
   */
  public void mkdirMain(final String cmd) 
  throws IOException {

    GetOpts g = new GetOpts(cmd, "h", 1);
    // get all Options
    int ch = g.getopt();
    while (ch != -1) {
      switch (ch) {
        case 'h':
          printHelp();
          return;
        case ':':         
          FSUtils.printError(out, "mkdir", g.getPath(), 99);
          return;  
        case '?':         
          FSUtils.printError(out, "mkdir", g.getPath(), 102);
          return;
      }      
      ch = g.getopt();
    }
    // if there is path expression remove it     
    if(g.getPath() != null) {      
      mkdir(g.getPath());
    } else {
      FSUtils.printError(out, "mkdir", "", 99);
    }
  }

  /**
   * Performs an mkdir command.
   *  
   *  @param path The name of the file
   *  @throws IOException in case of problems with the PrintOutput 
   */
  private void mkdir(final String path) throws IOException {

    String dir = "";
    int beginIndex = path.lastIndexOf('/');
    if(beginIndex == -1) {
      dir = path;
    } else {
      curDirPre = FSUtils.goToDir(context.data(), curDirPre, 
          path.substring(0, beginIndex));   
      if(curDirPre == -1) {
        FSUtils.printError(out, "mkdir", path, 2);     
        return;
      } else {
        dir = path.substring(beginIndex + 1);
      }
    }

    if(!FSUtils.validFileName(dir)) {
      FSUtils.printError(out, "mkdir", dir, 101);              
      return;
    }

    int source =  FSUtils.getOneSpecificDir(context.data(), 
        curDirPre, dir);
    if(source > -1) {
      FSUtils.printError(out, "mkdir", path, 17);
      return;


    } else {   
      // add new dir  
      try {
        int preNewFile = 4;
        if(!(curDirPre == FSUtils.getROOTDIR())) {
          preNewFile = curDirPre + FSUtils.NUMATT;
        }
        FSUtils.insert(context.data(), true, Token.token(dir), 
            Token.token(""), Token.token(0), 
            Token.token(System.currentTimeMillis()), curDirPre, preNewFile);
      } catch(Exception e) {
        e.printStackTrace();
      }
    }
  }


  /**
   * Print the help.
   * 
   * @throws IOException in case of problems with the PrintOutput
   */
  private void printHelp() throws IOException {
    out.print(FSMKDIR);

  }

}

