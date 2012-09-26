
// Dump all transactions affecting a specific address

#include <time.h>
#include <util.h>
#include <vector>
#include <common.h>
#include <rmd160.h>
#include <string.h>
#include <errlog.h>
#include <callback.h>
#include <stdio.h>

#define CBNAME "allTransactions"
enum  optionIndex { kUnknown };
static const option::Descriptor usageDescriptor[] =
{
    { kUnknown, 0, "",    "", option::Arg::None, "\n" },
    { 0,        0,  0,     0,                 0,                                          0 }
};

static uint8_t emptyKey[kRIPEMD160ByteSize] = { 0x52 };
typedef GoogMap<Hash160, int, Hash160Hasher, Hash160Equal>::Map AddrMap;

struct AllTransactions:public Callback
{
    uint64_t sum;
    uint64_t adds;
    uint64_t subs;
    uint64_t nbTX;
    uint64_t bTime;

    virtual bool needTXHash()
    {
        return true;
    }

    virtual int init(
        int argc,
        char *argv[]
    )
    {
        sum = 0;
        adds = 0;
        subs = 0;
        nbTX = 0;

        option::Stats  stats(usageDescriptor, argc, argv);
        option::Option *buffer  = new option::Option[stats.buffer_max];
        option::Option *options = new option::Option[stats.options_max];
        option::Parser parse(usageDescriptor, argc, argv, options, buffer);
        if(parse.error()) exit(1);

        delete [] options;
        delete [] buffer;
        return 0;
    }

    void move(
        const uint8_t *script,
        uint64_t      scriptSize,
        const uint8_t *txHash,
        uint64_t       value,
        bool           add,
        const uint8_t *downTXHash = 0
    )
    {
        uint8_t addrType[3];
        uint160_t pubKeyHash;
        int type = solveOutputScript(pubKeyHash.v, script, scriptSize, addrType);
        if(unlikely(type<0)) return;

        int64_t newSum = sum + value*(add ? 1 : -1);

        fwrite(&bTime, sizeof(uint64_t), 1, stdout);

        fwrite(pubKeyHash.v, sizeof(uint8_t), kRIPEMD160ByteSize, stdout); 
        //showHex(pubKeyHash.v, kRIPEMD160ByteSize, false);

        const uint8_t *hash = downTXHash ? downTXHash : txHash;  
        fwrite(hash, sizeof(uint8_t), kSHA256ByteSize, stdout);

        fwrite(&add, sizeof(uint8_t), 1, stdout);
        fwrite(&value, sizeof(uint64_t), 1, stdout);

        (add ? adds : subs) += value;
        sum = newSum;
        ++nbTX;
    }

    virtual void endOutput(
        const uint8_t *p,
        uint64_t      value,
        const uint8_t *txHash,
        uint64_t      outputIndex,
        const uint8_t *outputScript,
        uint64_t      outputScriptSize
    )
    {
        move(
            outputScript,
            outputScriptSize,
            txHash,
            value,
            true
        );
    }

    virtual void edge(
        uint64_t      value,
        const uint8_t *upTXHash,
        uint64_t      outputIndex,
        const uint8_t *outputScript,
        uint64_t      outputScriptSize,
        const uint8_t *downTXHash,
        uint64_t      inputIndex,
        const uint8_t *inputScript,
        uint64_t      inputScriptSize
    )
    {
        move(
            outputScript,
            outputScriptSize,
            upTXHash,
            value,
            false,
            downTXHash
        );
    }

    virtual void startBlock(
        const Block *b
    )
    {
        const uint8_t *p = b->data;
        SKIP(uint32_t, version, p);
        SKIP(uint256_t, prevBlkHash, p);
        SKIP(uint256_t, blkMerkleRoot, p);
        LOAD(uint32_t, blkTime, p);
        bTime = blkTime;

        struct tm gmTime;
        time_t blockTime = bTime;
        gmtime_r(&blockTime, &gmTime);

        char timeBuf[256];
        asctime_r(&gmTime, timeBuf);

        size_t sz =strlen(timeBuf);
        if(0<sz) timeBuf[sz-1] = 0;

	info("Processing block at time: %s", timeBuf);
    }

    virtual void start(
        const Block *,
        const Block *
    )
    {
    }

    virtual void wrapup()
    {
            info(
                "\n"
                "    transactions  = %" PRIu64 "\n"
                "    received      = %17.08f\n"
                "    spent         = %17.08f\n"
                "    balance       = %17.08f\n"
                "\n",
                nbTX,
                adds*1e-8,
                subs*1e-8,
                sum*1e-8
            );
    }

    virtual const option::Descriptor *usage() const
    {
        return usageDescriptor;
    }

    virtual const char *name() const
    {
        return CBNAME;
    }

    virtual void aliases(
        std::vector<const char*> &v
    )
    {
    }
};

static AllTransactions allTransactions;

