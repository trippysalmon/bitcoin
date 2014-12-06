// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include "serialize.h"

#include <stdlib.h>
#include <string>

class safe_bool_base {
protected:
    typedef void (safe_bool_base::*bool_type)() const;
    void this_type_does_not_support_comparisons() const {}

    safe_bool_base() {}
    safe_bool_base(const safe_bool_base&) {}
    safe_bool_base& operator=(const safe_bool_base&) {return *this;}
    ~safe_bool_base() {}
};

template <typename T=void> 
class safe_bool : public safe_bool_base {
public:
    operator bool_type() const {
        return (static_cast<const T*>(this))->boolean_test()
               ? &safe_bool_base::this_type_does_not_support_comparisons : 0;
    }
protected:
    ~safe_bool() {}
};

template <typename T, typename U> 
void operator==(const safe_bool<T>& lhs,const safe_bool<U>& rhs) {
    lhs.this_type_does_not_support_comparisons();	
    return false;
}

template <typename T,typename U> 
void operator!=(const safe_bool<T>& lhs,const safe_bool<U>& rhs) {
    lhs.this_type_does_not_support_comparisons();
    return false;	
}

template <typename T>
class TConstantAmount : public safe_bool< TConstantAmount<T> >
{
public:
    T n;
    TConstantAmount<T>() : n(0) { }
    TConstantAmount<T>(const T& _n): n(_n) { }
    TConstantAmount<T>(const TConstantAmount<T>& other) { n = other.n; }

    friend bool operator==(const TConstantAmount<T>& a, const TConstantAmount<T>& b) { return a.n == b.n; }
    friend bool operator!=(const TConstantAmount<T>& a, const TConstantAmount<T>& b) { return a.n == b.n; }
    friend bool operator< (const TConstantAmount<T>& a, const TConstantAmount<T>& b) { return a.n <  b.n; }
    friend bool operator> (const TConstantAmount<T>& a, const TConstantAmount<T>& b) { return a.n >  b.n; }
    friend bool operator<=(const TConstantAmount<T>& a, const TConstantAmount<T>& b) { return a.n <= b.n; }
    friend bool operator>=(const TConstantAmount<T>& a, const TConstantAmount<T>& b) { return a.n >= b.n; }

    friend bool operator==(const T& a, const TConstantAmount<T>& b) { return a == b.n; }
    /* friend bool operator!=(const T& a, const TConstantAmount<T>& b) { return a != b.n; } */
    friend bool operator< (const T& a, const TConstantAmount<T>& b) { return a <  b.n; }
    friend bool operator> (const T& a, const TConstantAmount<T>& b) { return a >  b.n; }
    friend bool operator<=(const T& a, const TConstantAmount<T>& b) { return a <= b.n; }
    friend bool operator>=(const T& a, const TConstantAmount<T>& b) { return a >= b.n; }
    friend bool operator==(const TConstantAmount<T>& a, const T& b) { return a.n == b; }
    /* friend bool operator!=(const TConstantAmount<T>& a, const T& b) { return a.n != b; } */
    friend bool operator< (const TConstantAmount<T>& a, const T& b) { return a.n <  b; }
    friend bool operator> (const TConstantAmount<T>& a, const T& b) { return a.n >  b; }
    friend bool operator<=(const TConstantAmount<T>& a, const T& b) { return a.n <= b; }
    friend bool operator>=(const TConstantAmount<T>& a, const T& b) { return a.n >= b; }

    friend std::ostream& operator<<(std::ostream& stream, const TConstantAmount<T>& a) { stream << a.n; return stream; }

    TConstantAmount<T>& operator=(const TConstantAmount<T>& b) { n = b.n; return *this; }
    bool boolean_test() const { return n != 0; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(n);
    }
};

template <typename T>
class TOperableAmount : public TConstantAmount<T>
{
public:
    TOperableAmount<T>() : TConstantAmount<T>(0) { }
    TOperableAmount<T>(const T& _n): TConstantAmount<T>(_n) { }

    /* friend TOperableAmount<T>& operator=(TOperableAmount<T>& a, const TOperableAmount<T>& b) { return a.n = b.n; } */

    friend TOperableAmount<T> operator+(const TOperableAmount<T>& a, const TOperableAmount<T>& b) { return a.n + b.n; }
    friend TOperableAmount<T> operator-(const TOperableAmount<T>& a, const TOperableAmount<T>& b) { return a.n - b.n; }
    friend TOperableAmount<T> operator*(const TOperableAmount<T>& a, const TOperableAmount<T>& b) { return a.n * b.n; }
    friend TOperableAmount<T> operator/(const TOperableAmount<T>& a, const TOperableAmount<T>& b) { return a.n / b.n; }
    friend TOperableAmount<T> operator%(const TOperableAmount<T>& a, const TOperableAmount<T>& b) { return a.n % b.n; }

    friend TOperableAmount<T>& operator+=(TOperableAmount<T>& a, const TOperableAmount<T>& b) { a.n += b.n; return a; }
    friend TOperableAmount<T>& operator-=(TOperableAmount<T>& a, const TOperableAmount<T>& b) { a.n -= b.n; return a; }
    friend TOperableAmount<T>& operator*=(TOperableAmount<T>& a, const TOperableAmount<T>& b) { a.n *= b.n; return a; }
    friend TOperableAmount<T>& operator/=(TOperableAmount<T>& a, const TOperableAmount<T>& b) { a.n /= b.n; return a; }
    friend TOperableAmount<T>& operator%=(TOperableAmount<T>& a, const TOperableAmount<T>& b) { a.n %= b.n; return a; }

    friend TOperableAmount<T> operator+(const T& a, const TOperableAmount<T>& b) { return a + b.n; }
    friend TOperableAmount<T> operator-(const T& a, const TOperableAmount<T>& b) { return a - b.n; }
    friend TOperableAmount<T> operator*(const T& a, const TOperableAmount<T>& b) { return a * b.n; }
    friend TOperableAmount<T> operator/(const T& a, const TOperableAmount<T>& b) { return a / b.n; }
    friend TOperableAmount<T> operator%(const T& a, const TOperableAmount<T>& b) { return a % b.n; }
    friend TOperableAmount<T> operator+(const TOperableAmount<T>& a, const T& b) { return a.n + b; }
    friend TOperableAmount<T> operator-(const TOperableAmount<T>& a, const T& b) { return a.n - b; }
    friend TOperableAmount<T> operator*(const TOperableAmount<T>& a, const T& b) { return a.n * b; }
    friend TOperableAmount<T> operator/(const TOperableAmount<T>& a, const T& b) { return a.n / b; }
    friend TOperableAmount<T> operator%(const TOperableAmount<T>& a, const T& b) { return a.n % b; }

    friend TOperableAmount<T> operator-(const TOperableAmount<T>& a) { return TOperableAmount<T>(-a.n); }
    friend TOperableAmount<T>& operator++(const TOperableAmount<T>& a) { ++a.n; return a; }

};

typedef TOperableAmount<int64_t> CAmount;
/* /\**  */
/*  * Type-safe wrapper class to for monetary amounts */
/*  *\/ */
/* class CAmount : public TOperableAmount<int64_t> */
/* { */
/* public: */
/*     CAmount() : TOperableAmount<int64_t>(0) { } */
/*     CAmount(const int64_t& _n): TOperableAmount<int64_t>(_n) { } */
/* }; */

/* typedef int64_t CAmount; */
/* static const CAmount COIN = 100000000; */
/* static const CAmount CENT = 1000000; */

/* /\** No amount larger than this (in satoshi) is valid *\/ */
/* static const CAmount MAX_MONEY = 21000000 * COIN; */
/* inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); } */

std::string AmountToString(const CAmount& n);
double AmountToDouble(const CAmount& n);

static const CAmount NULL_AMOUNT = -1;

static const int64_t COIN = 100000000;
static const int64_t CENT = 1000000;

/** No amount larger than this (in satoshi) is valid */
static const int64_t MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

/** Type-safe wrapper class to for fee rates
 * (how much to pay based on transaction size, unit is satoshis-per-1,000-bytes)
 */
class CFeeRate : public TConstantAmount<int64_t>
{
public:
    CFeeRate() : TConstantAmount<int64_t>(0) { }
    explicit CFeeRate(const int64_t& _n): TConstantAmount<int64_t>(_n) { }
    CFeeRate(const CAmount& _amount): TConstantAmount<int64_t>(_amount.n) { }
    CFeeRate(const CAmount& nFeePaid, size_t nSize);

    int64_t GetFee(size_t size) const; // unit returned is satoshis
    int64_t GetFeePerK() const { return GetFee(1000); } // satoshis-per-1000-bytes

    std::string ToString() const;
};

#endif //  BITCOIN_AMOUNT_H
