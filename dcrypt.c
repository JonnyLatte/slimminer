// Copyright (c) 2013-2014 The Slimcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>
#include <stdlib.h>
#include <math.h>          //pow

#include "miner.h"
#include "dcrypt.h"

//the base size for malloc/realloc will be 1KB
#define REALLOC_BASE_SZ   (1024)

unsigned int max_hashtable =  5;

const size_t item_size = sizeof(uint8_t[SHA256_LEN + 1]);
const size_t table_size = sizeof(uint8_t[SHA256_LEN + 1])*16;
const size_t ctx_table_size = sizeof(SHA256_CTX)*16;

uint8_t         * tmp_array_1 = 0;
SHA256_CTX		*      hash_1 = 0;
uint8_t         * tmp_array_2 = 0;
SHA256_CTX		*      hash_2 = 0;
uint8_t         * tmp_array_3 = 0;
SHA256_CTX		*      hash_3 = 0;
uint8_t         * tmp_array_4 = 0;
SHA256_CTX		*      hash_4 = 0;
uint8_t         * tmp_array_5 = 0;
SHA256_CTX		*      hash_5 = 0;

void cleanup_hashtable_memory()
{
	#define SAFE_FREE(X) if(X) free(X); X = 0;

	SAFE_FREE(tmp_array_1)
	SAFE_FREE(hash_1)
	SAFE_FREE(tmp_array_2)
	SAFE_FREE(hash_2)
	SAFE_FREE(tmp_array_3)
	SAFE_FREE(hash_3)
	SAFE_FREE(tmp_array_4)
	SAFE_FREE(hash_4)
	SAFE_FREE(tmp_array_5)
	SAFE_FREE(hash_5)
}

void init_hashtable_memory(unsigned int depth)
{	
	printf("Allocating memory for dcrypt bufferes.\n");

	switch (depth)
	{
	case 5:
		if(!(tmp_array_5 = (uint8_t*)malloc(table_size*16*16*16*16)))
		{
			printf("Failed to allocate memory 3\n");
		    cleanup_hashtable_memory();
			return;
		}
		if(!(hash_5 = (SHA256_CTX*)malloc(ctx_table_size*16*16*16*16)))
		{
			free(tmp_array_5);
			tmp_array_5 = 0;
			printf("Failed to allocate ctx memory 3\n");
			cleanup_hashtable_memory();
			return;
		}
	case 4:
		if(!(tmp_array_4 = (uint8_t*)malloc(table_size*16*16*16)))
		{
			printf("Failed to allocate memory 3\n");
			cleanup_hashtable_memory();
			return;
		}
		if(!(hash_4 = (SHA256_CTX*)malloc(ctx_table_size*16*16*16)))
		{
			free(tmp_array_4);
			tmp_array_4 = 0;
			printf("Failed to allocate ctx memory 3\n");
			cleanup_hashtable_memory();
			return;
		}
	case 3:
		if(!(tmp_array_3 = (uint8_t*)malloc(table_size*16*16)))
		{
			printf("Failed to allocate memory 3\n");
			cleanup_hashtable_memory();
			return;
		}
		if(!(hash_3 = (SHA256_CTX*)malloc(ctx_table_size*16*16)))
		{
			free(tmp_array_3);
			tmp_array_3 = 0;
			printf("Failed to allocate ctx memory 3\n");
			cleanup_hashtable_memory();
			return;
		}
	case 2:
		if(!(tmp_array_2 = (uint8_t*)malloc(table_size*16)))
		{
			printf("Failed to allocate memory 2\n");
			cleanup_hashtable_memory();
			return;
		}
		if(!(hash_2 = (SHA256_CTX*)malloc(ctx_table_size*16)))
		{
			free(tmp_array_2);
			tmp_array_2 = 0;
			printf("Failed to allocate ctx memory 2\n");
			cleanup_hashtable_memory();
			return;
		}
	case 1:
		if(!(tmp_array_1 = (uint8_t*)malloc(table_size)))
		{
			printf("Failed to allocate memory 1\n");
			cleanup_hashtable_memory();
			return;
		}
		if(!(hash_1 = (SHA256_CTX*)malloc(ctx_table_size)))
		{
			free(tmp_array_1);
			tmp_array_1 = 0;
			printf("Failed to allocate ctx memory 1\n");
			cleanup_hashtable_memory();
			return;
		}
	}
}

void init_hashtable_values()
{
	printf("Pre-computing dcrypt internal hash values.\n");

	SHA256_CTX	hash;
	SHA256_Init(&hash);
	unsigned char md[32];

	if(tmp_array_1 && hash_1)
	{
		for(int x1 = 0; x1 < 16; x1++)
		{
			unsigned int offset_1 = x1;
			uint8_t * ta1 = &tmp_array_1[item_size*x1];
			memset(ta1, 0xff, SHA256_LEN); 
			ta1[SHA256_LEN] = hex_digits[x1];
			sha256_to_str(ta1, SHA256_LEN + 1, ta1,md);

			SHA256_CTX	*current_hash = &hash_1[x1];
			memcpy(current_hash,&hash,sizeof(SHA256_CTX));
			SHA256_Update(current_hash,ta1,SHA256_LEN);

			if(tmp_array_2 && hash_2)
			{
				for(int x2 = 0; x2 < 16; x2++)
				{
					unsigned int offset_2 = offset_1*16+x2;
					uint8_t * ta2 = &tmp_array_2[item_size*offset_2];
					memcpy(ta2,ta1,SHA256_LEN); 
					ta2[SHA256_LEN] = hex_digits[x2];
					sha256_to_str(ta2, SHA256_LEN + 1, ta2,md);

					memcpy(&hash_2[offset_2],&hash_1[offset_1],sizeof(SHA256_CTX));
					SHA256_Update(&hash_2[offset_2],ta2,SHA256_LEN);

					if(tmp_array_3 && hash_3)
					{
						for(int x3 = 0; x3 < 16; x3++)
						{
							unsigned int offset_3 = offset_2*16+x3;
							uint8_t * ta3 = &tmp_array_3[item_size*offset_3];
							memcpy(ta3,ta2,SHA256_LEN); 
							ta3[SHA256_LEN] = hex_digits[x3];
							sha256_to_str(ta3, SHA256_LEN + 1, ta3,md);

							memcpy(&hash_3[offset_3],&hash_2[offset_2],sizeof(SHA256_CTX));
							SHA256_Update(&hash_3[offset_3],ta3,SHA256_LEN);

							if(tmp_array_4 && hash_4)
							{
								for(int x4 = 0; x4 < 16; x4++)
								{
									unsigned int offset_4 = offset_3*16+x4;
									uint8_t * ta4 = &tmp_array_4[item_size*offset_4];
									memcpy(ta4,ta3,SHA256_LEN); 
									ta4[SHA256_LEN] = hex_digits[x4];
									sha256_to_str(ta4, SHA256_LEN + 1, ta4,md);

									memcpy(&hash_4[offset_4],&hash_3[offset_3],sizeof(SHA256_CTX));
									SHA256_Update(&hash_4[offset_4],ta4,SHA256_LEN);

									if(tmp_array_5 && hash_5)
									{
										for(int x5 = 0; x5 < 16; x5++)
										{
											unsigned int offset_5 = offset_4*16+x5;
											uint8_t * ta5 = &tmp_array_5[item_size*offset_5];
											memcpy(ta5,ta4,SHA256_LEN); 
											ta5[SHA256_LEN] = hex_digits[x5];
											sha256_to_str(ta5, SHA256_LEN + 1, ta5,md);

											memcpy(&hash_5[offset_5],&hash_4[offset_4],sizeof(SHA256_CTX));
											SHA256_Update(&hash_5[offset_5],ta5,SHA256_LEN);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	printf("Ready to rumble.\n");
}

void init_dcrypt_hashtables(unsigned int depth)
{
	if(!depth) return;

	init_hashtable_memory(depth);	
	init_hashtable_values();
}

typedef struct
{
  uint8_t *array;
  unsigned long long actual_array_sz;
  uint32_t times_realloced;

} Extend_Array;

inline void Extend_Array_init(Extend_Array *ExtArray)
{
  //initial values
  ExtArray->array = 0;
  ExtArray->actual_array_sz = 0;
  ExtArray->times_realloced = 0;
  return;
}

uint32_t hex_char_to_int(uint8_t c)
{
  if(c > 47 && c < 58)
    return c - 47;

  if(c > 96 && c < 103)
    return 10 + c - 96;

  if(c > 64 && c < 71)
    return 10 + c - 64;

  return 0;
}

inline void join_to_array(uint8_t *array, uint8_t join)
{
  *(array + SHA256_LEN) = join;
  return;
}

void extend_array(Extend_Array *extend_array, unsigned long long used_array_sz, 
                  uint8_t *extend, uint32_t extend_sz, uint8_t hashed_end, int max_iter)
{
  if(!extend_array)
    return;

  //if there is not enough room
  if((extend_array->actual_array_sz - used_array_sz) < (extend_sz + hashed_end))
  {
    //if extend_array->array has already been malloc'd
    if(extend_array->times_realloced)
    {
      //reallocate on an exponential curve, modern computers have plenty ram
      extend_array->actual_array_sz += (2 << extend_array->times_realloced++) * (max_iter * 64 + SHA256_DIGEST_LENGTH);
      extend_array->array = realloc(extend_array->array, extend_array->actual_array_sz);
    }else{
      //allocate the base size
      extend_array->actual_array_sz += max_iter * 64 + SHA256_DIGEST_LENGTH;
      extend_array->times_realloced++;

      extend_array->array = malloc(extend_array->actual_array_sz); //if we have not allocated anything, malloc
    }
  }

  //copy the data to be extended
  memcpy(extend_array->array + used_array_sz, extend, extend_sz);

  if(hashed_end)   
    *(extend_array->array + used_array_sz + extend_sz) = 0; //add the final \000 of the whole string array

  return;
}

uint64 mix_hashed_nums(uint8_t *hashed_nums, const uint8_t *unhashedData, size_t unhashed_sz,
                       uint8_t **mixed_hash, uint8_t *hash_digest, int num_iter, bool *completed)
{
  uint32_t index = 0;
  const uint32_t hashed_nums_len = SHA256_LEN;

  uint64 count;
  uint8_t tmp_val, tmp_array[SHA256_LEN + 2];

  //initialize the class for the extend hash
  Extend_Array new_hash;
  Extend_Array_init(&new_hash);

  //set the first hash length in the temp array to all 0xff
  memset(tmp_array, 0xff, SHA256_LEN);
  //set the last two bytes to \000
  *(tmp_array + SHA256_LEN) = *(tmp_array + SHA256_LEN + 1) = 0;

  for(count = 0; count < num_iter; count++)
  {
    //+1 to keeps a 0 value of *(hashed_nums + index) moving on
    index += hex_char_to_int(*(hashed_nums + index));
    
    //if we hit the end of the hash, rehash it
    if(index >= hashed_nums_len)
    {
      index = index & (hashed_nums_len - 1);
      sha256_to_str(hashed_nums, hashed_nums_len, hashed_nums, hash_digest); //rescramble
    }
    
    tmp_val = *(hashed_nums + index);

    join_to_array(tmp_array, tmp_val); //plop tmp_val at the end of tmp_array
    sha256_to_str(tmp_array, SHA256_LEN + 1, tmp_array, hash_digest);

    //extend the expanded hash to the array
    extend_array(&new_hash, count * SHA256_LEN, tmp_array, SHA256_LEN, false, num_iter);

    //check if the last value of hashed_nums is the same as the last value in tmp_array
    if(index == hashed_nums_len - 1 && tmp_val == *(tmp_array + SHA256_LEN - 1))
	{
      //add to count since we extended the array, but break will exit the for loop and count
      // will not get incremenented by the for loop
      count++;
      break;
	}
  }
  if (count == num_iter) *completed = false;
  else *completed = true;
  //extend the unhashed data to the end and add the \000 to the end
  extend_array(&new_hash, count * SHA256_LEN, (u8int*)unhashedData, unhashed_sz, true, num_iter);

  //assign the address of new_hash's array to mixed_hash
  *mixed_hash = new_hash.array;

  return count * SHA256_LEN + unhashed_sz;
}

u8int *dcrypt_buffer_alloc()
{
  return malloc(DCRYPT_DIGEST_LENGTH);
}

bool dcrypt(const uint8_t *data, size_t data_sz, uint8_t *hash_digest, u32int *hashRet, int num_iter)
{
  uint8_t hashed_nums[SHA256_LEN + 1], *mix_hash;

  bool allocDigest = false;
  bool completed = false;
  if(!hash_digest)
  {
    hash_digest = alloca(DCRYPT_DIGEST_LENGTH);
    allocDigest = true;
  }

  sha256_to_str(data, data_sz, hashed_nums, hash_digest);

  //mix the hashes up, magority of the time takes here
  uint64 mix_hash_len = mix_hashed_nums(hashed_nums, data, data_sz, &mix_hash, hash_digest, num_iter, &completed);

  //apply the final hash to the output
  if (completed)  sha256((const uint8_t*)mix_hash, mix_hash_len, hashRet);

  free(mix_hash);

  //sucess
  return completed;
}


inline void digest_to_skiplist(unsigned char *d, unsigned char *str)
{
	for (register int i = SHA256_DIGEST_LENGTH; i ; --i) {
        *str++ = (*d & 0xf0) >> 4;
        *str++ = (*d & 0x0f);
        d++;
    }   
	*str = 0;
    return;
}

bool dcrypt_fast(u8int *data, size_t data_sz,uint32_t*md)
{
	#define MAX_INC 16

	unsigned char hash_buffer[SHA256_LEN*MAX_INC+SHA256_LEN*4+80+1];  

	unsigned char		index_buffer[SHA256_LEN+1]; 
	unsigned char 		*tmp_array = hash_buffer;     
	unsigned int	    index = 0;
	unsigned char		tmp_val;

	SHA256_CTX	hash;
	SHA256_Init(&hash);

	digest_to_skiplist((u8int *)md,index_buffer);   

	int steps = 0,index_test=index;
	while(1)
	{
		index_test += index_buffer[index_test]+1;

		if(index_test >= SHA256_LEN) return 0;
		if(index_test == SHA256_LEN - 1) break;
		steps++;
	}
	if(steps >= MAX_INC) return 0;/**/

	memset(tmp_array, 0xff, SHA256_LEN);      //set the first hash length in the temp array to all 0xff'
	memset(tmp_array + SHA256_LEN, 0x00, 2);  //set the last bytes to \000

	int count = 0; 

	if(tmp_array_1 && hash_1) // copy pre-calulated internal hashes
	{
		index += index_buffer[index]+1;
		unsigned int offset_1 = index_buffer[index];

		if(tmp_array_2 && hash_2) // depth 2
		{
			index += index_buffer[index]+1;
			unsigned int offset_2 = offset_1*16+index_buffer[index];

			if(tmp_array_3 && hash_3) // depth 3
			{
				index += index_buffer[index]+1;
				unsigned int offset_3 = offset_2*16+index_buffer[index];

				if(tmp_array_4 && hash_4) // depth 4
				{
					index += index_buffer[index]+1;
					unsigned int offset_4 = offset_3*16+index_buffer[index];

					if(tmp_array_5 && hash_5) // depth 5
					{
						index += index_buffer[index]+1;
						unsigned int offset_5 = offset_4*16+index_buffer[index];

						// depth 6?

						memcpy(tmp_array,&tmp_array_5[item_size*offset_5],SHA256_LEN); 
						memcpy(&hash,&hash_5[offset_5],sizeof(SHA256_CTX));
					}
					else
					{
						memcpy(tmp_array,&tmp_array_4[item_size*offset_4],SHA256_LEN); 
						memcpy(&hash,&hash_4[offset_4],sizeof(SHA256_CTX));
					}
				}
				else
				{
					memcpy(tmp_array,&tmp_array_3[item_size*offset_3],SHA256_LEN); 
					memcpy(&hash,&hash_3[offset_3],sizeof(SHA256_CTX));
				}
			}
			else
			{
				memcpy(tmp_array,&tmp_array_2[item_size*offset_2],SHA256_LEN); 
				memcpy(&hash,&hash_2[offset_2],sizeof(SHA256_CTX));
			}
		}
		else {
			memcpy(tmp_array,&tmp_array_1[item_size*offset_1],SHA256_LEN); 
			memcpy(&hash,&hash_1[offset_1],sizeof(SHA256_CTX));
		}
	}

 	do
	{
		index += index_buffer[index]+1;

		if(index >= SHA256_LEN) return 0;
	
		tmp_val = hex_digits[index_buffer[index]];

		tmp_array[SHA256_LEN] =  tmp_val; //set  end of tmp_array to tmp_val
		sha256_to_str(tmp_array, SHA256_LEN + 1, tmp_array+SHA256_LEN,(u8int *)md);

		count++;
		tmp_array += SHA256_LEN;

	}
	while ((index != SHA256_LEN - 1) || (tmp_val != tmp_array[SHA256_LEN - 1] ));

	SHA256_Update(&hash,hash_buffer+SHA256_LEN,SHA256_LEN*count);
	SHA256_Update(&hash,data,data_sz);
	SHA256_Final((u8int *)md, &hash);

	return 1;
}

int scanhash_dcrypt(int thr_id, uint32_t *pdata,
                    unsigned char *digest, const uint32_t *ptarget,
                    uint32_t max_nonce, unsigned long *hashes_done, int num_iter)
{
  uint32_t block[20], hash[8];
  uint32_t nNonce = pdata[19] - 1;
  const uint32_t Htarg = ptarget[7]; //the last element in the target is the first 32 bits of the target
  int i;
  bool completed;
  int missed = 0;	
  //copy the block (first 80 bytes of pdata) into block
  memcpy(block, pdata, 80);

  SHA256_CTX	halfstate,fullstate;
  SHA256_Init(&halfstate);
  SHA256_Update(&halfstate,&block,sizeof(uint32_t)*19);
  
  do
  {
    //increment nNonce
    block[19] = ++nNonce;
		
    //completed = dcrypt((u8int*)block, 80, digest, hash, num_iter);

	memcpy(&fullstate,&halfstate,sizeof(SHA256_CTX)); 
	SHA256_Update(&fullstate,&block[19],sizeof(uint32_t));
	SHA256_Final((u8int *)hash, &fullstate);
	completed = dcrypt_fast((u8int*)block, 80,hash);/**/

    if (!completed)
    {
        missed += 1;
        continue;
    }

	/*
	// check optimized hash against previous hash function

	uint32_t hash2[8];

	int c2 = dcrypt((u8int*)block, 80, digest, hash2, num_iter);

	for(int i = 0; i < 8 ; i++)
	{
		if(hash[i] != hash2[i])
		{
			char s1[65],s2[65];
			digest_to_string((u8int*)hash, s1);
			digest_to_string((u8int*)hash2, s2);
			printf("Fail!!!\n%s %d\n%s %d\n",s1,completed,s2,c2);
			exit(0);
		}
	}/**/


    //hash[7] <= Htarg just compares the first 32 bits of the hash with the target
    // full_test fully compares the entire hash with the entire target

    if(hash[7] <= Htarg && fulltest(hash, ptarget)) 
    {
      *hashes_done = nNonce - pdata[19] + 1 - missed;
      pdata[19] = block[19];

		char s[65];
		digest_to_string((u8int*)hash, s);
	    applog(LOG_INFO, "hash found: %s", s);

		// check

		uint32_t hash2[8];

		int c2 = dcrypt((u8int*)block, 80, digest, hash2, num_iter);

		for(int i = 0; i < 8 ; i++)
		{
			if(hash[i] != hash2[i])
			{
				char s1[65],s2[65];
				digest_to_string((u8int*)hash, s1);
				digest_to_string((u8int*)hash2, s2);
				printf("Error invalid hash found.\n%s %d\n%s %d\n",s1,completed,s2,c2);
				exit(0);
			}
		}
		//printf("hash verified.\n");

      //found a hash!
      return 1;
    }

  }while(nNonce < max_nonce && !work_restart[thr_id].restart);
	
  *hashes_done = nNonce - pdata[19] + 1 - missed;
  pdata[19] = nNonce;

  //No luck yet
  return 0;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////
//////////////////// Various tests
////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

/* Tests the comparison to two hashes

//Hash the word "Dog" with Dcrypt and strinify the hash
u32int ret[8];
char string[65];
dcrypt("Dog", 3, 0, ret);
digest_to_string((u8int*)ret, string);
printf("String is %s\n", string);

//hash the word "Doge" with Dcrypt and stringify the hash
u32int ret2[8];
char string2[65];
dcrypt("Doge", 4, 0, ret2);
digest_to_string((u8int*)ret2, string2);
printf("String2 is %s\n", string2);

//compare the last elements, which correspond the the uint256's first 32 bytes
if(ret[7] < ret2[7])
printf("String1 is smaller %08x < %08x\n", ret[7], ret2[7]);
else
printf("String1 is greater %08x >= %08x\n", ret[7], ret2[7]);

//Apply the full test to make sure
printf("Full test returns %d\n", fulltest(ret2, ret));

*/

/* Tests the scan feature of dcrypt
   u8int digest[DCRYPT_DIGEST_LENGTH], string[65], strTarget[65];
   unsigned long hDone;
   u32int pdata[20], retHash[8], target[8];

   //fill pdata with something
   memset(pdata, 0xff, 20 * sizeof(u32int));
   pdata[19] = 0; //element 19 is the beginning of where nNonce begins

   //fill the target with 1's
   memset(target, 0xff, 8 * sizeof(u32int));
   //the last element is the uint256's first 32 bits, set the target to 0x00000ffffffffff....
   target[7] = 0x000ffff;

   //scan for them hashes
   scanhash_dcrypt(0, pdata, digest, target, -1, &hDone);

   //Get the hash of pdata
   dcrypt((u8int*)pdata, 80, digest, retHash);

   //stringify the returned hash and the target
   digest_to_string((u8int*)retHash, string);
   digest_to_string((u8int*)target, strTarget);

   printf("  Hash is %s %08x\n", string, retHash[7]);
   printf("Target is %s %08x\n", strTarget, target[7]);
   printf("Nonce %d Hashes Done %ld\n", pdata[19], hDone);
*/

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////
//////////////////// Various tests
////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
