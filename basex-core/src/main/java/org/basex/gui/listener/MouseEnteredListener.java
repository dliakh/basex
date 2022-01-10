package org.basex.gui.listener;

import java.awt.event.*;

/**
 * Listener interface for handling mouse clicks.
 *
 * @author BaseX Team 2005-22, BSD License
 * @author Christian Gruen
 */
public interface MouseEnteredListener extends MouseListener {
  @Override
  default void mouseClicked(final MouseEvent e) { }

  @Override
  default void mouseExited(final MouseEvent e) { }

  @Override
  default void mousePressed(final MouseEvent e) { }

  @Override
  default void mouseReleased(final MouseEvent e) { }
}
