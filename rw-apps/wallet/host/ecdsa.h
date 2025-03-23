/** \file ecdsa.h
  *
  * \brief Describes functions, types and constants exported and used by
  *        ecdsa.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef ECDSA_H_INCLUDED
#define ECDSA_H_INCLUDED

#include "common.h"

/** Maximum size, in bytes, of a serialised elliptic curve point, as is
  * written by ecdsaSerialise(). */
#define ECDSA_MAX_SERIALISE_SIZE	65

/** A point on the elliptic curve, in affine coordinates. Affine
  * coordinates are the (x, y) that satisfy the elliptic curve
  * equation y ^ 2 = x ^ 3 + a * x + b.
  */
typedef struct PointAffineStruct
{
	/** x component of a point in affine coordinates. */
	uint8_t x[32];
	/** y component of a point in affine coordinates. */
	uint8_t y[32];
	/** If is_point_at_infinity is non-zero, then this point represents the
	  * point at infinity and all other structure members are considered
	  * invalid. */
	uint8_t is_point_at_infinity;
} PointAffine;

/** A point on the elliptic curve, in Jacobian coordinates. The
  * Jacobian coordinates (x, y, z) are related to affine coordinates
  * (x_affine, y_affine) by:
  * (x_affine, y_affine) = (x / (z ^ 2), y / (z ^ 3)).
  *
  * Why use Jacobian coordinates? Because then point addition and
  * point doubling don't have to use inversion (division), which is very slow.
  */
typedef struct PointJacobianStruct
{
  /** x component of a point in Jacobian coordinates. */
  uint8_t x[32];
  /** y component of a point in Jacobian coordinates. */
  uint8_t y[32];
  /** z component of a point in Jacobian coordinates. */
  uint8_t z[32];
  /** If is_point_at_infinity is non-zero, then this point represents the
    * point at infinity and all other structure members are considered
    * invalid. */
  uint8_t is_point_at_infinity;
} PointJacobian;

#endif /* #ifndef ECDSA_H_INCLUDED */
