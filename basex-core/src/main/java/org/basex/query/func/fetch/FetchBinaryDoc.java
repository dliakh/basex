package org.basex.query.func.fetch;

import org.basex.io.*;
import org.basex.query.*;
import org.basex.query.value.item.*;
import org.basex.util.*;

/**
 * Function implementation.
 *
 * @author BaseX Team 2005-22, BSD License
 * @author Christian Gruen
 */
public final class FetchBinaryDoc extends FetchDoc {
  @Override
  public Item item(final QueryContext qc, final InputInfo ii) throws QueryException {
    final IO io = new IOContent(toBin(exprs[0], qc).binary(info));
    return fetch(io, qc);
  }
}
