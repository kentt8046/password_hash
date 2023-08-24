/// The cost to use when stretching a password.
class StretchingCost {
  const StretchingCost._();

  /// The minimum allowed cost.
  static const minCost = 4;

  /// The maximum allowed cost.
  static const maxCost = 31;

  /// The default cost to use.
  static const defaultCost = 10;
}
