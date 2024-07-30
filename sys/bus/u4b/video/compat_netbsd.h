/* grr, #defines for gratuitous incompatibility in queue.h */
#define	SIMPLEQ_HEAD		STAILQ_HEAD
#define	SIMPLEQ_ENTRY		STAILQ_ENTRY
#define	SIMPLEQ_INIT		STAILQ_INIT
#define	SIMPLEQ_INSERT_TAIL	STAILQ_INSERT_TAIL
#define	SIMPLEQ_EMPTY		STAILQ_EMPTY
#define	SIMPLEQ_FIRST		STAILQ_FIRST
#define	SIMPLEQ_REMOVE_HEAD	STAILQ_REMOVE_HEAD
#define	SIMPLEQ_FOREACH		STAILQ_FOREACH
/* ditto for endian.h */
#define	letoh16(x)		le16toh(x)
#define	letoh32(x)		le32toh(x)

