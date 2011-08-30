/**
 * @file Typedefs and tricks to make NS-3 code compiles without changing all types
 */

#ifndef _NS3_COMPAT_H_
#define _NS3_COMPAT_H_

#include <sys/types.h>
#include <boost/shared_ptr.hpp>

#define Ptr boost::shared_ptr

#define NOT_NS3 1 // there is a totally incompatible code :(

template<class T>
boost::shared_ptr<T> Create() { return boost::shared_ptr<T> (new T()); }

template<class T, class P1>
boost::shared_ptr<T> Create(P1 &p1) { return boost::shared_ptr<T> (new T(p1)); }

template<class T, class P1, class P2>
boost::shared_ptr<T> Create(P1 &p1, P2 p2) { return boost::shared_ptr<T> (new T(p1, p2)); }

template<class T, class P1, class P2, class P3>
boost::shared_ptr<T> Create(P1 &p1, P2 p2, P3 p3) { return boost::shared_ptr<T> (new T(p1, p2, p3)); }

//template<class To, class From>
//boost::shared_ptr<T> StaticCast (From &
template<class T, class U>
boost::shared_ptr<T> StaticCast(boost::shared_ptr<U> const & r) { return boost::static_pointer_cast<T>(r); }

template<class T, class U>
boost::shared_ptr<T> DynamicCast(boost::shared_ptr<U> const & r) { return boost::dynamic_pointer_cast<T>(r); }

typedef unsigned char uint8_t; // types.h defines  u_char

class Buffer : public boost::shared_ptr<char>
{
public:
  class Iterator : public std::istream
  {
  public:
	uint8_t ReadU8 () { return static_cast<uint8_t> (get ()); }
	uint8_t PeekU8 () { return static_cast<uint8_t> (peek ()); }
	bool IsEnd () const { return eof(); }
  };
};

#undef CCN_CLOSE

template<class T>
class SimpleRefCount
{
};

class Time
{
  public:
	enum {S=0, NS=1};

	Time (long long sec, long long ns)
		: m_sec (sec)
		, m_ns (ns) {}
	
	static
	Time FromInteger(long long value, uint8_t unit)
	{
		if (unit==S)
			return Time (value,0);
		else if (unit==NS)
			return Time (0, value);
	}

	Time operator+ (const Time &o)
	{
		return Time (m_sec+o.m_sec, m_ns+o.m_ns);
	}

	long long m_sec;
	long long m_ns;
};

#endif // _NS3_COMPAT_H_
