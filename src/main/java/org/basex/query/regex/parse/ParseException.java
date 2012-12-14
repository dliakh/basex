/* Generated By:JavaCC: Do not edit this line. ParseException.java Version 5.0 */
/* JavaCCOptions:KEEP_LINE_COL=null */
package org.basex.query.regex.parse;

/**
 * This exception is thrown when parse errors are encountered.
 * You can explicitly create objects of this exception type by
 * calling the method generateParseException in the generated
 * parser.
 *
 * You can modify this class to customize your error reporting
 * mechanisms so long as you retain the public fields.
 */
public class ParseException extends Exception {

  /**
   * The version identifier for this Serializable class.
   * Increment only if the <i>serialized</i> form of the
   * class changes.
   */
  private static final long serialVersionUID = 1L;

  /**
   * This constructor is used by the method "generateParseException"
   * in the generated parser.  Calling this constructor generates
   * a new object of this type with the fields "currentToken",
   * "expectedTokenSequences", and "tokenImage" set.
   * @param curr current token
   * @param exps expected token sequences
   * @param imgs image strings
   */
  public ParseException(final Token curr, final int[][] exps, final String[] imgs) {
    super(initialise(curr, exps, imgs));
    currentToken = curr;
    expectedTokenSequences = exps;
    tokenImage = imgs;
  }

  /**
   * The following constructors are for use by you for whatever
   * purpose you can think of.  Constructing the exception in this
   * manner makes the exception behave in the normal way - i.e., as
   * documented in the class "Throwable".  The fields "errorToken",
   * "expectedTokenSequences", and "tokenImage" do not contain
   * relevant information.  The JavaCC generated code does not use
   * these constructors.
   */

  public ParseException() {
    super();
  }

  /** Constructor with message.
   * @param message error message
   */
  public ParseException(final String message) {
    super(message);
  }

  /**
   * This is the last token that has been consumed successfully.  If
   * this object has been created due to a parse error, the token
   * followng this token will (therefore) be the first error token.
   */
  public Token currentToken;

  /**
   * Each entry in this array is an array of integers.  Each array
   * of integers represents a sequence of tokens (by their ordinal
   * values) that is expected at this point of the parse.
   */
  public int[][] expectedTokenSequences;

  /**
   * This is a reference to the "tokenImage" array of the generated
   * parser within which the parse error occurred.  This array is
   * defined in the generated ...Constants interface.
   */
  public String[] tokenImage;

  /**
   * It uses "currentToken" and "expectedTokenSequences" to generate a parse
   * error message and returns it.  If this object has been created
   * due to a parse error, and you do not catch it (it gets thrown
   * from the parser) the correct error message
   * gets displayed.
   * @param curr current token
   * @param exps expected token sequences
   * @param img token images
   * @return error description
   */
  private static String initialise(final Token curr, final int[][] exps,
      final String[] img) {
    final String eol = System.getProperty("line.separator", "\n");
    final StringBuilder expected = new StringBuilder();
    int maxSize = 0;
    for(final int[] exp : exps) {
      if(maxSize < exp.length) {
        maxSize = exp.length;
      }
      for(final int e : exp) {
        expected.append(img[e]).append(' ');
      }
      if(exp[exp.length - 1] != 0) {
        expected.append("...");
      }
      expected.append(eol).append("    ");
    }
    String retval = "Encountered \"";
    Token tok = curr.next;
    for (int i = 0; i < maxSize; i++) {
      if(i != 0) retval += " ";
      if(tok.kind == 0) {
        retval += img[0];
        break;
      }
      retval += " " + img[tok.kind];
      retval += " \"";
      retval += addEscapes(tok.image);
      retval += " \"";
      tok = tok.next;
    }
    retval += "\" at line " + curr.next.beginLine + ", column " + curr.next.beginColumn;
    retval += "." + eol;
    if (exps.length == 1) {
      retval += "Was expecting:" + eol + "    ";
    } else {
      retval += "Was expecting one of:" + eol + "    ";
    }
    retval += expected.toString();
    return retval;
  }

  /**
   * The end of line string for this machine.
   */
  protected String eol = System.getProperty("line.separator", "\n");

  /**
   * Used to convert raw characters to their escaped version
   * when these raw version cannot be used as part of an ASCII
   * string literal.
   * @param str string to escape
   * @return escaped string
   */
  static String addEscapes(final String str) {
      final StringBuilder retval = new StringBuilder();
      char ch;
      for (int i = 0; i < str.length(); i++) {
        switch (str.charAt(i)) {
           case 0 :
              continue;
           case '\b':
              retval.append("\\b");
              continue;
           case '\t':
              retval.append("\\t");
              continue;
           case '\n':
              retval.append("\\n");
              continue;
           case '\f':
              retval.append("\\f");
              continue;
           case '\r':
              retval.append("\\r");
              continue;
           case '\"':
              retval.append("\\\"");
              continue;
           case '\'':
              retval.append("\\\'");
              continue;
           case '\\':
              retval.append("\\\\");
              continue;
           default:
              if((ch = str.charAt(i)) < 0x20 || ch > 0x7e) {
                 final String s = "0000" + Integer.toString(ch, 16);
                 retval.append("\\u" + s.substring(s.length() - 4, s.length()));
              } else {
                 retval.append(ch);
              }
              continue;
        }
      }
      return retval.toString();
   }

}
/* JavaCC - OriginalChecksum=82d3ef24b529ba07ce7fc2f9b7c8efa1 (do not edit this line) */
