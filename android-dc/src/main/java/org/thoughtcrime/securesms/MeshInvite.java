package org.thoughtcrime.securesms;

import java.util.UUID;

/**
 * Utility class for generating and parsing EpsilonChat mesh invite strings.
 *
 * <p>Invites use the format {@code epsilon://<uuid>}, e.g. {@code
 * epsilon://550e8400-e29b-41d4-a716-446655440000}.
 */
public final class MeshInvite {

  public static final String SCHEME = "epsilon";

  private MeshInvite() {
    // utility class
  }

  /** Generate a fresh random invite string in the form {@code epsilon://<uuid>}. */
  public static String generateInvite() {
    return SCHEME + "://" + UUID.randomUUID();
  }

  /**
   * Parse an invite string and return {@code true} if it has the valid {@code epsilon://<uuid>}
   * format.
   */
  public static boolean parseInvite(String invite) {
    if (invite == null) return false;
    String id = getInviteId(invite);
    if (id == null) return false;
    try {
      //noinspection ResultOfMethodCallIgnored
      UUID.fromString(id);
      return true;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /** Extract the UUID part from an invite string, or {@code null} if malformed. */
  public static String getInviteId(String invite) {
    if (invite == null) return null;
    String prefix = SCHEME + "://";
    if (!invite.startsWith(prefix)) return null;
    String rest = invite.substring(prefix.length());
    if (rest.isEmpty()) return null;
    // strip any trailing path/query/fragment so a pasted URL still parses
    int cut = rest.indexOf('/');
    if (cut > 0) rest = rest.substring(0, cut);
    int q = rest.indexOf('?');
    if (q > 0) rest = rest.substring(0, q);
    int h = rest.indexOf('#');
    if (h > 0) rest = rest.substring(0, h);
    return rest;
  }
}