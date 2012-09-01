#ifndef BNAUTH_BIT_CONVERTER_H__
#define BNAUTH_BIT_CONVERTER_H__

#include <limits>

namespace BNAuth
{
	class BitConverter
	{
	public:
		template <bool BigEndian, typename OutTy, typename CharPtr>
		static OutTy Convert(CharPtr buffer)
		{
			typedef std::numeric_limits<OutTy> I;

			if (BigEndian)
			{
				buffer += I::digits / CHAR_BIT + !!(I::digits % CHAR_BIT) - 1;
			}

			OutTy val(BigEndian ? *buffer-- : *buffer++);

			for (int shiftBy = CHAR_BIT; shiftBy < I::digits; shiftBy += CHAR_BIT)
			{
				val |= OutTy(BigEndian ? *buffer-- : *buffer++) << shiftBy; 
			}

			return val;
		}
	};
}

#endif