#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(__FreeBSD__)
#include <malloc.h>
#endif
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>
#if defined(__FreeBSD__)
#include <sys/stat.h>
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_SRD
#include <infiniband/efadv.h>
#endif

#include "perftest_resources.h"
#include "raw_ethernet_resources.h"

static enum ibv_wr_opcode opcode_verbs_array[] = {IBV_WR_SEND,IBV_WR_RDMA_WRITE,IBV_WR_RDMA_WRITE_WITH_IMM,IBV_WR_RDMA_READ};
static enum ibv_wr_opcode opcode_atomic_array[] = {IBV_WR_ATOMIC_CMP_AND_SWP,IBV_WR_ATOMIC_FETCH_AND_ADD};

#define CPU_UTILITY "/proc/stat"
#define DC_KEY 0xffeeddcc

/* Initialize dynamic polling context */
static struct dyn_poll_ctx *init_dyn_poll_ctx(struct perftest_parameters *user_param)
{
	struct dyn_poll_ctx *ctx;
	ALLOCATE(ctx, struct dyn_poll_ctx, 1);

	/* Initialize with const config */
	ctx->config.min = 16;
	ctx->config.max = 1024;
	ctx->config.stabilize = 10;
	ctx->config.threshold = 0.85;

	ctx->state.curr_size = user_param->dynamic_cqe_poll ? 1024 : user_param->cqe_poll;
	ctx->state.stable_iters = 0;
	ctx->state.last_ne = 0;

	ctx->stabilization_iters = (user_param->test_type == ITERATIONS) ?
		MIN(user_param->iters / 4, MAX_QP_NUM) :
		MAX(user_param->num_of_qps * 3, 1000);

	return ctx;
}

static __always_inline int poll_cq_adaptive(
	struct ibv_cq *cq,
	struct ibv_wc *wc,
	const struct dyn_cqe_poll_config *config,
	struct dyn_poll_state *state,
	int *dynamic_enabled)
{
	int ne = ibv_poll_cq(cq, state->curr_size, wc);

	if (ne == state->curr_size && state->curr_size < config->max) {
		state->curr_size = (uint16_t)MIN((state->curr_size + ne) / 2, config->max);
		state->stable_iters = 0;
	} else if (ne < state->curr_size * config->threshold) {
		if (state->curr_size > config->min) {
			state->curr_size = (uint16_t)MAX((state->curr_size + ne) / 2, config->min);
			state->stable_iters = 0;
		}
	} else if (ne == state->last_ne) {
		if (++state->stable_iters >= config->stabilize) {
			*dynamic_enabled = 0;
		}
	} else {
		state->stable_iters = 0;
	}
	state->last_ne = ne;

	return ne;
}
static __always_inline int poll_completions(
	struct ibv_cq *cq,
	struct ibv_wc *wc,
	struct dyn_poll_ctx *dyn_ctx,
	uint64_t curr_count,
	int *dynamic_enabled)
{
	if (*dynamic_enabled && curr_count < dyn_ctx->stabilization_iters) {
		return poll_cq_adaptive(
			cq,
			wc,
			&dyn_ctx->config,
			&dyn_ctx->state,
			dynamic_enabled
		);
	}
	return ibv_poll_cq(cq, dyn_ctx->state.curr_size, wc);
}

struct perftest_parameters* duration_param;
struct check_alive_data check_alive_data;


/******************************************************************************
 * Beginning
 ******************************************************************************/

#ifdef HAVE_AES_XTS
int set_valid_dek(char *dst, struct perftest_parameters *user_param)
{
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	int index = 0;
	char* eptr;
	char* execute = NULL;
	int i;
	int size;

	const char file_name_letters[] = "abcdefghijklmnopqrstuvwxyz1234567890";
	char file_path[AES_XTS_DEK_FILE_NAME_SIZE];
	int file_letters_size = sizeof(file_name_letters)-1;
	FILE* dek_file = NULL;

	srand (time (NULL));

	sprintf(file_path, "/tmp/");

	/* + 5 because we begin to randomize after folder path /tmp/ */
	for(i = 5; i < AES_XTS_DEK_FILE_NAME_SIZE - 1; i++) {
		file_path[i] = file_name_letters[rand() % file_letters_size];
	}

	/* + 1 for the '\0' at the end of the char array*/
	size = strlen(user_param->data_enc_key_app_path) + 1
		+ strlen(user_param->kek_path) + 1 + strlen(file_path) + 1;

	ALLOCATE(execute, char, size);

	strcpy(execute, user_param->data_enc_key_app_path);
	strcat(execute, " ");
	strcat(execute, user_param->kek_path);
	strcat(execute, " ");
	strcat(execute, file_path);

	if(system(execute)) {
		fprintf(stderr, "Execution of %s has failed\n", execute);
		free(execute);
		return FAILURE;
	}

	free(execute);

	dek_file = fopen(file_path, "r");

	if(dek_file == NULL) {
		fprintf(stderr, "Can not open the data_encryption_key file\n");
		return FAILURE;
	}

	while((read = getline(&line, &len, dek_file)) != -1) {

		if(index >= AES_XTS_DEK_SIZE) {
			fprintf(stderr, "Invalid data_encryption_key file\n");
			fclose(dek_file);
			return FAILURE;
		}

		dst[index] = strtol(line, &eptr, 16);
		index++;
	}

	fclose(dek_file);

	remove(file_path);

	return 0;
}

int set_valid_cred(char *dst, struct perftest_parameters *user_param)
{
	char valid_credential[48];
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	char* eptr;
	int index = 0;
	FILE* cred = NULL;

	cred = fopen(user_param->credentials_path, "r");

	if(cred == NULL) {
		fprintf(stderr, "Can not open the credentials file\n");
		return FAILURE;
	}

	while((read = getline(&line, &len, cred)) != -1) {

		if(index >= AES_XTS_CREDENTIALS_SIZE) {
			fprintf(stderr, "Invalid credentials file\n");
			fclose(cred);
			return FAILURE;
		}

		valid_credential[index] = strtol(line, &eptr, 16);
		index++;
	}

	fclose(cred);

	//coverity[uninit_use_in_call]
	memcpy(dst, valid_credential, sizeof(valid_credential));

	return 0;
}
#endif

#ifdef HAVE_SIG_OFFLOAD
static void set_sig_domain(struct pingpong_context *ctx){
	memset(ctx->t10dif_sig, 0, sizeof(struct mlx5dv_sig_t10dif));
	ctx->t10dif_sig->bg_type = MLX5DV_SIG_T10DIF_CRC;
	ctx->t10dif_sig->bg = 0xffff;
	ctx->t10dif_sig->app_tag = 0x5678;
	ctx->t10dif_sig->ref_tag = 0xabcdef90;
	ctx->t10dif_sig->flags = MLX5DV_SIG_T10DIF_FLAG_REF_REMAP |
		     MLX5DV_SIG_T10DIF_FLAG_APP_ESCAPE;

	memset(ctx->domain, 0, sizeof(struct mlx5dv_sig_block_domain));
	ctx->domain->sig.dif = ctx->t10dif_sig;
	ctx->domain->sig_type = MLX5DV_SIG_TYPE_T10DIF;
	ctx->domain->block_size = MLX5DV_BLOCK_SIZE_512;
}

#endif

static uint32_t perftest_rand(uint32_t *state) {
    uint32_t x = *state;
    *state = x * 747796405 + 2891336453;
    uint32_t word = ((x >> ((x >> 28) + 4)) ^ x) * 277803737;
    return (word >> 22) ^ word;
}

// Proper initialization the rand algorithm
static uint32_t init_perftest_rand_state() {
    uint32_t seed;

    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(&seed, sizeof(seed), 1, f) == 1) {
            fclose(f);
            return seed;
        }
        fclose(f);
    }

    seed = (uint32_t)time(NULL);
    seed ^= (uint32_t)getpid();
    seed ^= (uint32_t)clock();

    return seed;
}

// cppcheck-suppress constParameter
static int next_word_string(char* input, char* output, int from_index)
{
	int i = from_index;
	int j = 0;

	while (input[i] != ' ') {
		output[j] = input[i];
		j++; i++;
	}

	output[j]=0;
	return i+1;
}

static int get_n_word_string(char *input, char *output,int from_index, int iters)
{
	for (;iters > 0; iters--) {
		from_index = next_word_string(input,output,from_index);
	}

	return from_index;
}
static void compress_spaces(char *str, char *dst)
{
	for (; *str; ++str) {
		*dst++ = *str;

		if (isspace(*str)) {
			do ++str;

			while (isspace(*str));

			--str;
		}
	}

	*dst = 0;
}

static void get_cpu_stats(struct perftest_parameters *duration_param,int stat_index)
{
	char* file_name = CPU_UTILITY;
	FILE *fp;
	fp = fopen(file_name, "r");

	if (fp != NULL) {
		char line[100];
		if (fgets(line,100,fp) != NULL) {
			char tmp[100];
			int index=0;
			compress_spaces(line,line);
			index=get_n_word_string(line,tmp,index,2); /* skip first word */
			duration_param->cpu_util_data.ustat[stat_index-1] = atoll(tmp);

			get_n_word_string(line,tmp,index,3); /* skip 2 stats */
			duration_param->cpu_util_data.idle[stat_index-1] = atoll(tmp);

		}
		fclose(fp);
	}
}

/* _new_post_send.
 *
 * Description :
 *
 * Does efficient posting of work to a send
 * queue using function calls instead of the struct based *ibv_post_send()*
 * scheme. Inline is used to make sure that switch would be decided on
 * compile time.
 *
 * Parameters :
 *
 *	ctx             - Test Context.
 *	user_param      - user_parameters struct for this test.
 *	inl             - use inline or not.
 *	index           - qp index.
 *	qpt             - qp type.
 *	op              - RDMA operation code.
 *	connection_type - Type of the connection.
 *	enc             - use encryption/decryption or not.
 *
 * Return Value : int.
 *
 */
#ifdef HAVE_IBV_WR_API
static inline int _new_post_send(struct pingpong_context *ctx,
	struct perftest_parameters *user_param, int inl, int index,
	enum ibv_qp_type qpt, enum ibv_wr_opcode op, int connection_type, int enc)
	__attribute__((always_inline));
static inline int _new_post_send(struct pingpong_context *ctx,
	struct perftest_parameters *user_param, int inl, int index,
	enum ibv_qp_type qpt, enum ibv_wr_opcode op, int connection_type, int enc)
{
	int rc;
	int wr_index = index * user_param->post_list;
	struct ibv_send_wr *wr = &ctx->wr[wr_index];

#ifdef HAVE_AES_XTS
	if(enc) {
		int i;
		struct ibv_sge sgl;
		struct mlx5dv_mkey_conf_attr mkey_attr = {};
		struct mlx5dv_crypto_attr crypto_attr = {};

		ibv_wr_start(ctx->qpx[index]);

		ctx->qpx[index]->wr_flags = IBV_SEND_INLINE;
		crypto_attr.crypto_standard = MLX5DV_CRYPTO_STANDARD_AES_XTS;
		sgl.addr = (uintptr_t)ctx->mr[index]->addr;
		sgl.lkey = ctx->mr[index]->lkey;
		sgl.length = user_param->buff_size;

		mlx5dv_wr_mkey_configure(ctx->dv_qp[index], ctx->mkey[index], 3, &mkey_attr);
		mlx5dv_wr_set_mkey_access_flags(ctx->dv_qp[index], IBV_ACCESS_REMOTE_READ |
                              IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);
		mlx5dv_wr_set_mkey_layout_list(ctx->dv_qp[index], 1, &sgl);

		if(user_param->sig_before) {
			crypto_attr.signature_crypto_order = MLX5DV_SIGNATURE_CRYPTO_ORDER_SIGNATURE_BEFORE_CRYPTO_ON_TX;
		}
		else {
			crypto_attr.signature_crypto_order = MLX5DV_SIGNATURE_CRYPTO_ORDER_SIGNATURE_AFTER_CRYPTO_ON_TX;
		}

		if(user_param->encrypt_on_tx) {
			crypto_attr.encrypt_on_tx = true;
		}
		else {
			crypto_attr.encrypt_on_tx = false;
		}

		for(i=0; i < AES_XTS_TWEAK_SIZE; i++) {
			crypto_attr.initial_tweak[i] = i;
		}

		for(i=0; i < AES_XTS_KEYTAG_SIZE; i++) {
			crypto_attr.keytag[i] = 0;
		}

		crypto_attr.data_unit_size = user_param->aes_block_size;
		crypto_attr.dek = ctx->dek[(ctx->dek_number%user_param->data_enc_keys_number)];
		ctx->dek_number++;

		mlx5dv_wr_set_mkey_crypto(ctx->dv_qp[index], &crypto_attr);
		ibv_wr_complete(ctx->qpx[index]);
	}
#endif

#ifdef HAVE_SIG_OFFLOAD
	if (user_param->sig_offload){
		struct mlx5dv_sig_block_attr sig_attr = {
			.mem = NULL,
			.wire = ctx->domain,
			.check_mask = MLX5DV_SIG_MASK_T10DIF_GUARD |
						MLX5DV_SIG_MASK_T10DIF_APPTAG |
						MLX5DV_SIG_MASK_T10DIF_REFTAG
		};

		struct mlx5dv_mkey_conf_attr conf_attr = {};
		uint32_t access_flags = IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_READ |
					IBV_ACCESS_REMOTE_WRITE;
		struct ibv_sge sgl;

		ibv_wr_start(ctx->qpx[index]);
		ctx->qpx[index]->wr_flags = IBV_SEND_INLINE;

		mlx5dv_wr_mkey_configure(ctx->dv_qp[index], ctx->mkey[index], 3, &conf_attr);
		mlx5dv_wr_set_mkey_access_flags(ctx->dv_qp[index], access_flags);

		sgl.addr = (uintptr_t)ctx->mr[index]->addr;
		sgl.lkey = ctx->mr[index]->lkey;
		sgl.length = user_param->buff_size;

		mlx5dv_wr_set_mkey_layout_list(ctx->dv_qp[index], 1, &sgl);

		mlx5dv_wr_set_mkey_sig_block(ctx->dv_qp[index], &sig_attr);

		if(ibv_wr_complete(ctx->qpx[index])) {
			fprintf(stderr, "MKEY T10DIF configuration failed: ibv_wr_complete failed.\n");
			return -1;
		}
	}
#endif

	ibv_wr_start(ctx->qpx[index]);
	while (wr)
	{
		ctx->qpx[index]->wr_id = wr->wr_id;
		ctx->qpx[index]->wr_flags = wr->send_flags;

		switch (op)
		{
		case IBV_WR_SEND:
			ibv_wr_send(ctx->qpx[index]);
			break;
		case IBV_WR_RDMA_WRITE:
			ibv_wr_rdma_write(
				ctx->qpx[index],
				wr->wr.rdma.rkey,
				wr->wr.rdma.remote_addr);
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			ibv_wr_rdma_write_imm(
				ctx->qpx[index],
				wr->wr.rdma.rkey,
				wr->wr.rdma.remote_addr, 0);
			break;
		case IBV_WR_RDMA_READ:
			ibv_wr_rdma_read(
				ctx->qpx[index],
				wr->wr.rdma.rkey,
				wr->wr.rdma.remote_addr);
			break;
		case IBV_WR_ATOMIC_FETCH_AND_ADD:
			ibv_wr_atomic_fetch_add(
				ctx->qpx[index],
				wr->wr.atomic.rkey,
				wr->wr.atomic.remote_addr,
				wr->wr.atomic.compare_add);
			break;
		case IBV_WR_ATOMIC_CMP_AND_SWP:
			ibv_wr_atomic_cmp_swp(
				ctx->qpx[index],
				wr->wr.atomic.rkey,
				wr->wr.atomic.remote_addr,
				wr->wr.atomic.compare_add,
				wr->wr.atomic.swap);
			break;
		default:
			fprintf(stderr, "Post send failed: unknown operation code.\n");
		}
		#ifdef HAVE_MLX5DV
		if (qpt == IBV_QPT_DRIVER && connection_type == DC)
		{
			#ifdef HAVE_DCS
			mlx5dv_wr_set_dc_addr_stream(
				ctx->dv_qp[index],
				ctx->ah[index],
				ctx->r_dctn[index],
				DC_KEY,
				ctx->dci_stream_id[index]);
			ctx->dci_stream_id[index] = (ctx->dci_stream_id[index] + 1) & (0xffffffff >> (32 - (user_param->log_active_dci_streams)));
			#else
			mlx5dv_wr_set_dc_addr(
				ctx->dv_qp[index],
				ctx->ah[index],
				ctx->r_dctn[index],
				DC_KEY);
			#endif
		}
		else
		#endif
		if (qpt == IBV_QPT_UD) {
			ibv_wr_set_ud_addr(
				ctx->qpx[index],
				wr->wr.ud.ah,
				wr->wr.ud.remote_qpn,
				wr->wr.ud.remote_qkey);
		} else if (qpt == IBV_QPT_DRIVER && connection_type == SRD) {
			ibv_wr_set_ud_addr(
				ctx->qpx[index],
				ctx->ah[index],
				ctx->rem_qpn[index],
				DEF_QKEY);
		}

		#ifdef HAVE_XRCD
		else if (qpt == IBV_QPT_XRC_SEND)
		{
			ibv_wr_set_xrc_srqn(
				ctx->qpx[index],
				wr->qp_type.xrc.remote_srqn);
		}
		#endif

		if (inl)
		{
			ibv_wr_set_inline_data(
				ctx->qpx[index],
				(void*) wr->sg_list->addr,
				user_param->size);
		}
		else
		{
			#ifdef HAVE_AES_XTS
			if(enc) {
				ctx->qpx[index]->wr_flags = ctx->qpx[index]->wr_flags | IBV_SEND_SIGNALED;
				ibv_wr_set_sge(ctx->qpx[index],
					ctx->mkey[index]->lkey,
					(uintptr_t)0,
					user_param->size);
			}
			else
			#endif
			ibv_wr_set_sge(
				ctx->qpx[index],
				wr->sg_list->lkey,
				wr->sg_list->addr,
				user_param->size);
		}
		wr = wr->next;
	}
	rc = ibv_wr_complete(ctx->qpx[index]);

	return rc;
}

/* new_post_send_*.
 *
 * Description :
 *
 * Calls _new_post_send to do posting of work to a send
 * queue using function calls instead of the struct based *ibv_post_send()*
 * scheme. We need a lot of functions for each combination to make sure the
 * condition in _new_post_send is decided in compile-time.
 *
 * Parameters :
 *
 *	ctx         - Test Context.
 *	index       - qp index.
 *	user_param  - user_parameters struct for this test.
 *
 * Return Value : int.
 *
 */
static int new_post_write_sge_dc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, opcode_verbs_array[user_param->verb], DC, 0);
}

static int new_post_write_inl_dc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_DRIVER, opcode_verbs_array[user_param->verb], DC, 0);
}

static int new_post_read_sge_dc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, IBV_WR_RDMA_READ, DC, 0);
}

static int new_post_send_sge_dc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, IBV_WR_SEND, DC, 0);
}

static int new_post_send_inl_dc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_DRIVER, IBV_WR_SEND, DC, 0);
}

static int new_post_atomic_fa_sge_dc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, IBV_WR_ATOMIC_FETCH_AND_ADD, DC, 0);
}

static int new_post_atomic_cs_sge_dc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, IBV_WR_ATOMIC_CMP_AND_SWP, DC, 0);
}

static int new_post_send_sge_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, IBV_WR_SEND, RC, 0);
}

static int new_post_send_sge_enc_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, IBV_WR_SEND, RC, 1);
}

static int new_post_send_inl_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_RC, IBV_WR_SEND, RC, 0);
}

static int new_post_write_sge_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, opcode_verbs_array[user_param->verb], RC, 0);
}

static int new_post_write_sge_enc_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, opcode_verbs_array[user_param->verb], RC, 1);
}

static int new_post_write_inl_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_RC, opcode_verbs_array[user_param->verb], RC, 0);
}

static int new_post_read_sge_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, IBV_WR_RDMA_READ, RC, 0);
}

static int new_post_read_sge_enc_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, IBV_WR_RDMA_READ, RC, 1);
}

static int new_post_atomic_fa_sge_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, IBV_WR_ATOMIC_FETCH_AND_ADD, RC, 0);
}

static int new_post_atomic_cs_sge_rc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_RC, IBV_WR_ATOMIC_CMP_AND_SWP, RC, 0);
}

static int new_post_send_sge_ud(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_UD, IBV_WR_SEND, UD, 0);
}

static int new_post_send_inl_ud(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_UD, IBV_WR_SEND, UD, 0);
}

static int new_post_send_sge_uc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_UC, IBV_WR_SEND, UC, 0);
}

static int new_post_send_inl_uc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_UC, IBV_WR_SEND, UC, 0);
}

static int new_post_write_sge_uc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_UC, opcode_verbs_array[user_param->verb], UC, 0);
}

static int new_post_write_inl_uc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_UC, opcode_verbs_array[user_param->verb], UC, 0);
}

static int new_post_send_sge_srd(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, IBV_WR_SEND, SRD, 0);
}

static int new_post_send_inl_srd(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_DRIVER, IBV_WR_SEND, SRD, 0);
}

static int new_post_read_sge_srd(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, IBV_WR_RDMA_READ, SRD, 0);
}

static int new_post_write_sge_srd(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_DRIVER, opcode_verbs_array[user_param->verb], SRD, 0);
}

static int new_post_write_inl_srd(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
       return _new_post_send(ctx, user_param, 1, index, IBV_QPT_DRIVER, opcode_verbs_array[user_param->verb], SRD, 0);
}

#ifdef HAVE_XRCD
static int new_post_send_sge_xrc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_XRC_SEND, IBV_WR_SEND, XRC, 0);
}

static int new_post_send_inl_xrc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_XRC_SEND, IBV_WR_SEND, XRC, 0);
}

static int new_post_write_sge_xrc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_XRC_SEND, opcode_verbs_array[user_param->verb], XRC, 0);
}

static int new_post_write_inl_xrc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 1, index, IBV_QPT_XRC_SEND, opcode_verbs_array[user_param->verb], XRC, 0);
}

static int new_post_read_sge_xrc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_XRC_SEND, IBV_WR_RDMA_READ, XRC, 0);
}

static int new_post_atomic_fa_sge_xrc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_XRC_SEND, IBV_WR_ATOMIC_FETCH_AND_ADD, XRC, 0);
}

static int new_post_atomic_cs_sge_xrc(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	return _new_post_send(ctx, user_param, 0, index, IBV_QPT_XRC_SEND, IBV_WR_ATOMIC_CMP_AND_SWP, XRC, 0);
}
#endif
#endif

/* post_send_method.
 *
 * Description :
 *
 * Does posting of work to a send queue.
 *
 * Parameters :
 *
 *	ctx         - Test Context.
 *	index       - qp index.
 *	user_param  - user_parameters struct for this test.
 *
 * Return Value : int.
 *
 */
static inline int post_send_method(struct pingpong_context *ctx, int index,
	struct perftest_parameters *user_param)
{
	#ifdef HAVE_IBV_WR_API
	if (!user_param->use_old_post_send)
		return (*ctx->new_post_send_work_request_func_pointer)(ctx, index, user_param);
	#endif
	struct ibv_send_wr 	*bad_wr = NULL;
	return ibv_post_send(ctx->qp[index], &ctx->wr[index*user_param->post_list], &bad_wr);

}

#ifdef HAVE_XRCD
/******************************************************************************
 *
 ******************************************************************************/
static int ctx_xrcd_create(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	char *tmp_file_name;
	struct ibv_xrcd_init_attr xrcd_init_attr;

	memset(&xrcd_init_attr , 0 , sizeof xrcd_init_attr);

	tmp_file_name = (user_param->machine == SERVER) ? SERVER_FD : CLIENT_FD;

	ctx->fd = open(tmp_file_name, O_RDONLY | O_CREAT, S_IRUSR | S_IRGRP);
	if (ctx->fd < 0) {
		fprintf(stderr,"Error opening file %s errno: %s\n", tmp_file_name,strerror(errno));
		return FAILURE;
	}

	xrcd_init_attr.comp_mask = IBV_XRCD_INIT_ATTR_FD | IBV_XRCD_INIT_ATTR_OFLAGS;
	xrcd_init_attr.fd = ctx->fd;
	xrcd_init_attr.oflags = O_CREAT ;

	ctx->xrc_domain = ibv_open_xrcd(ctx->context,&xrcd_init_attr);
	if (ctx->xrc_domain == NULL) {
		fprintf(stderr,"Error opening XRC domain\n");
		return FAILURE;
	}
	return 0;
}

/******************************************************************************
 *
 ******************************************************************************/
static int ctx_xrc_srq_create(struct pingpong_context *ctx,
			      struct perftest_parameters *user_param)
{
	struct ibv_srq_init_attr_ex srq_init_attr;

	memset(&srq_init_attr, 0, sizeof(srq_init_attr));

	srq_init_attr.attr.max_wr = user_param->rx_depth;
	srq_init_attr.attr.max_sge = 1;
	srq_init_attr.comp_mask = IBV_SRQ_INIT_ATTR_TYPE | IBV_SRQ_INIT_ATTR_XRCD | IBV_SRQ_INIT_ATTR_CQ | IBV_SRQ_INIT_ATTR_PD;
	srq_init_attr.srq_type = IBV_SRQT_XRC;
	srq_init_attr.xrcd = ctx->xrc_domain;

	if(user_param->verb == SEND || user_param->verb == WRITE_IMM)
		srq_init_attr.cq = ctx->recv_cq;
	else
		srq_init_attr.cq = ctx->send_cq;

	srq_init_attr.pd = ctx->pad;

	ctx->srq = ibv_create_srq_ex(ctx->context, &srq_init_attr);
	if (ctx->srq == NULL) {
		fprintf(stderr, "Couldn't open XRC SRQ\n");
		return FAILURE;
	}

	return 0;
}

/******************************************************************************
 *
 ******************************************************************************/
static struct ibv_qp *ctx_xrc_qp_create(struct pingpong_context *ctx,
					struct perftest_parameters *user_param,
					int qp_index)
{
	struct ibv_qp* qp = NULL;
	int num_of_qps = user_param->num_of_qps / 2;

	#ifdef HAVE_IBV_WR_API
	enum ibv_wr_opcode opcode;
	#endif

	struct ibv_qp_init_attr_ex qp_init_attr;

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	if ( (!(user_param->duplex || user_param->tst == LAT) && (user_param->machine == SERVER) )
			|| ((user_param->duplex || user_param->tst == LAT) && (qp_index >= num_of_qps))) {
		qp_init_attr.qp_type = IBV_QPT_XRC_RECV;
		qp_init_attr.comp_mask = IBV_QP_INIT_ATTR_XRCD;
		qp_init_attr.xrcd = ctx->xrc_domain;
		qp_init_attr.cap.max_recv_wr  = user_param->rx_depth;
		qp_init_attr.cap.max_recv_sge = 1;
		qp_init_attr.cap.max_inline_data = user_param->inline_size;

	} else {
		qp_init_attr.qp_type = IBV_QPT_XRC_SEND;
		qp_init_attr.send_cq = ctx->send_cq;
		qp_init_attr.cap.max_send_wr = user_param->tx_depth;
		qp_init_attr.cap.max_send_sge = 1;
		qp_init_attr.comp_mask = IBV_QP_INIT_ATTR_PD;
		qp_init_attr.pd = ctx->pad;

		#ifdef HAVE_IBV_WR_API
		if (!user_param->use_old_post_send)
			qp_init_attr.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
		#endif
		qp_init_attr.cap.max_inline_data = user_param->inline_size;
	}

	#ifdef HAVE_IBV_WR_API
	if (!user_param->use_old_post_send)
	{
		if (user_param->verb == ATOMIC)
		{
			opcode = opcode_atomic_array[user_param->atomicType];
			if (opcode == IBV_WR_ATOMIC_FETCH_AND_ADD)
				qp_init_attr.send_ops_flags |= IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD;
			else if (opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
				qp_init_attr.send_ops_flags |= IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP;
		}
		else
		{
			opcode = opcode_verbs_array[user_param->verb];
			if (opcode == IBV_WR_SEND)
				qp_init_attr.send_ops_flags |= IBV_QP_EX_WITH_SEND;
			else if (opcode == IBV_WR_RDMA_WRITE)
				qp_init_attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE;
			else if (opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
				qp_init_attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM;
			else if (opcode == IBV_WR_RDMA_READ)
				qp_init_attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_READ;
		}
	}
	#endif

	qp = ibv_create_qp_ex(ctx->context, &qp_init_attr);

	return qp;
}
#endif

/******************************************************************************
 *
 ******************************************************************************/
int check_add_port(char **service,int port,
		const char *servername,
		struct addrinfo *hints,
		struct addrinfo **res)
{
	int number;

	if (asprintf(service,"%d", port) < 0) {
		return FAILURE;
	}

	number = getaddrinfo(servername,*service,hints,res);

	free(*service);

	if (number < 0) {
		fprintf(stderr, "%s for ai_family: %x service: %s port: %d\n",
				gai_strerror(number), hints->ai_family, servername, port);
		return FAILURE;
	}

	return SUCCESS;
}

/******************************************************************************
 *
 ******************************************************************************/
int sockaddr_set_port(struct sockaddr *sin,int port)
{
	switch (sin->sa_family) {
	case AF_INET:  ((struct sockaddr_in*) sin)->sin_port = htons(port);
		break;
	case AF_INET6:  ((struct sockaddr_in6*) sin)->sin6_port = htons(port);
		break;
	default:
		fprintf(stderr, "ai_family: %x is not yet supported\n", sin->sa_family);
		return FAILURE;
	}
	return SUCCESS;
}
/******************************************************************************
 *
 ******************************************************************************/
int create_rdma_resources(struct pingpong_context *ctx,
		struct perftest_parameters *user_param)
{
	int is_udp_ps = user_param->connection_type == UD || user_param->connection_type == RawEth;
	enum rdma_port_space port_space = (is_udp_ps) ? RDMA_PS_UDP : RDMA_PS_TCP;
	struct rdma_cm_id **cm_id = (user_param->machine == CLIENT) ? &ctx->cm_id : &ctx->cm_id_control;

	ctx->cm_channel = rdma_create_event_channel();
	if (ctx->cm_channel == NULL) {
		fprintf(stderr, " rdma_create_event_channel failed\n");
		return FAILURE;
	}

	if (rdma_create_id(ctx->cm_channel,cm_id,NULL,port_space)) {
		fprintf(stderr,"rdma_create_id failed\n");
		goto destroy_event_channel;
	}

	return SUCCESS;

destroy_event_channel:
	rdma_destroy_event_channel(ctx->cm_channel);
	return FAILURE;

}

/******************************************************************************
 *
 ******************************************************************************/
int destroy_rdma_resources(struct pingpong_context *ctx,
		struct perftest_parameters *user_param)
{
	int ret;
	if (user_param->machine == CLIENT) {
		ret = rdma_destroy_id(ctx->cm_id);
	} else {
		ret = rdma_destroy_id(ctx->cm_id_control);
	}
	rdma_destroy_event_channel(ctx->cm_channel);
	return ret;
}

/******************************************************************************
 *
 ******************************************************************************/
struct ibv_device* ctx_find_dev(char **ib_devname)
{
	int num_of_device;
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev = NULL;

	dev_list = ibv_get_device_list(&num_of_device);

	//coverity[uninit_use]
	if (num_of_device <= 0) {
		fprintf(stderr," Did not detect devices \n");
		fprintf(stderr," If device exists, check if driver is up\n");
		return NULL;
	}

	if (!ib_devname) {
		fprintf(stderr," Internal error, existing.\n");
		return NULL;
	}

	if (!*ib_devname) {
		ib_dev = dev_list[0];
		if (!ib_dev) {
			fprintf(stderr, "No IB devices found\n");
			exit (1);
		}
	} else {
		for (; (ib_dev = *dev_list); ++dev_list)
			if (!strcmp(ibv_get_device_name(ib_dev), *ib_devname))
				break;
		if (!ib_dev) {
			fprintf(stderr, "IB device %s not found\n", *ib_devname);
			return NULL;
		}
	}

	GET_STRING(*ib_devname, ibv_get_device_name(ib_dev));
	return ib_dev;
}

/******************************************************************************
 *
 ******************************************************************************/
struct ibv_context* ctx_open_device(struct ibv_device *ib_dev, struct perftest_parameters *user_param)
{
	struct ibv_context *context;

#ifdef HAVE_AES_XTS
	if(user_param->aes_xts){
		struct mlx5dv_crypto_login_attr login_attr = {};
		struct mlx5dv_context_attr attr = {};
		attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;

		if(set_valid_cred(login_attr.credential, user_param)){
			fprintf(stderr, "Couldn't set credentials\n");
			return NULL;
		}

		context = mlx5dv_open_device(ib_dev, &attr);

		if(!context){
			fprintf(stderr, "Couldn't get context for the device\n");
			return NULL;
		}

		int ret = mlx5dv_crypto_login(context, &login_attr);

		if (ret) {
			fprintf(stderr,"Couldn't login. err=%d.\n", ret);
			return NULL;
		}

		return context;
	}
#endif

	context = ibv_open_device(ib_dev);

	if (!context) {
		fprintf(stderr, " Couldn't get context for the device\n");
		return NULL;
	}

	return context;
}
/******************************************************************************
 *
 ******************************************************************************/
/* alloc_ctx 函数: 分配测试上下文所需的所有资源
 *
 * 这个函数是内存分配的核心入口，负责分配：
 * 1. 数据缓冲区指针数组（ctx->buf）
 * 2. 实际的数据缓冲区（通过 memory_create 回调）
 * 3. QP、MR、WQE 等 RDMA 资源的指针数组
 * 4. 时间戳和计数器数组
 *
 * CLIENT 和 SERVER 的内存使用区别：
 * - CLIENT: 需要发送缓冲区（源数据）+ 接收缓冲区（如果双工模式）
 * - SERVER: 需要接收缓冲区（被 CLIENT WRITE 的目标内存）
 *
 * 内存分配后会被注册为 MR（Memory Region），使得 RDMA 硬件可以访问
 */
int alloc_ctx(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	uint64_t tarr_size;
	int num_of_qps_factor;
	ctx->cycle_buffer = user_param->cycle_buffer;
	ctx->cache_line_size = user_param->cache_line_size;

	/* 分配每个 QP 的端口映射数组 */
	ALLOC(user_param->port_by_qp, uint64_t, user_param->num_of_qps);

	/* 分配时间戳数组，用于性能测量
	 * - BW 测试：记录每次迭代的开始时间
	 * - LAT 测试：记录发送和接收时间戳
	 */
	tarr_size = (user_param->noPeak) ? 1 : user_param->iters*user_param->num_of_qps;
	ALLOC(user_param->tposted, cycles_t, tarr_size);
	memset(user_param->tposted, 0, sizeof(cycles_t)*tarr_size);
	if ((user_param->tst == LAT || user_param->tst == FS_RATE) && user_param->test_type == DURATION)
		ALLOC(user_param->tcompleted, cycles_t, 1);

	/* 分配 QP 指针数组，每个 QP 对应一个通信通道 */
	ALLOC(ctx->qp, struct ibv_qp*, user_param->num_of_qps);
	#ifdef HAVE_IBV_WR_API
	ALLOC(ctx->qpx, struct ibv_qp_ex*, user_param->num_of_qps);
	#ifdef HAVE_MLX5DV
	ALLOC(ctx->dv_qp, struct mlx5dv_qp_ex*, user_param->num_of_qps);
	ALLOC(ctx->mkey, struct mlx5dv_mkey*, user_param->num_of_qps);
	#endif
	ALLOC(ctx->r_dctn, uint32_t, user_param->num_of_qps);
	#ifdef HAVE_DCS
	ALLOC(ctx->dci_stream_id, uint32_t, user_param->num_of_qps);
	memset(ctx->dci_stream_id, 0, user_param->num_of_qps * sizeof (uint32_t));
	#endif
	#ifdef HAVE_AES_XTS
	ALLOC(ctx->dek, struct mlx5dv_dek*, user_param->data_enc_keys_number);
	#endif
	#ifdef HAVE_SIG_OFFLOAD
	ALLOC(ctx->domain, struct mlx5dv_sig_block_domain, 1);
	ALLOC(ctx->t10dif_sig, struct mlx5dv_sig_t10dif, 1);
	#endif
	#endif
	/* 分配 MR (Memory Region) 指针数组
	 * MR 是注册后的内存区域，包含 lkey 和 rkey
	 * - CLIENT: MR 用于本地数据访问（lkey）
	 * - SERVER: MR 的 rkey 需要发送给 CLIENT，供 RDMA WRITE 使用
	 */
	ALLOC(ctx->mr, struct ibv_mr*, user_param->num_of_qps);

	/* 【关键】分配数据缓冲区指针数组
	 * ctx->buf[i] 将指向实际分配的内存缓冲区
	 * 这里只分配指针数组，实际内存在后面通过 memory_create 分配
	 *
	 * 在 RDMA WRITE 测试中：
	 * - CLIENT: ctx->buf[] 存放要写入的源数据
	 * - SERVER: ctx->buf[] 是被 CLIENT WRITE 的目标内存
	 */
	ALLOC(ctx->buf, void*, user_param->num_of_qps);

	if ((user_param->tst == BW || user_param->tst == LAT_BY_BW) && (user_param->machine == CLIENT || user_param->duplex)) {

		ALLOC(user_param->tcompleted,cycles_t,tarr_size);
		memset(user_param->tcompleted, 0, sizeof(cycles_t)*tarr_size);
		ALLOC(ctx->my_addr,uint64_t,user_param->num_of_qps);
		ALLOC(ctx->rem_addr,uint64_t,user_param->num_of_qps);
		ALLOC(ctx->scnt,uint64_t,user_param->num_of_qps);
		ALLOC(ctx->ccnt,uint64_t,user_param->num_of_qps);
		memset(ctx->scnt, 0, user_param->num_of_qps * sizeof (uint64_t));
		memset(ctx->ccnt, 0, user_param->num_of_qps * sizeof (uint64_t));

	} else if ((user_param->tst == BW || user_param->tst == LAT_BY_BW)
		   && (user_param->verb == SEND || user_param->verb == WRITE_IMM) && user_param->machine == SERVER) {

		ALLOC(ctx->my_addr, uint64_t, user_param->num_of_qps);
		ALLOC(user_param->tcompleted, cycles_t, 1);
	} else if (user_param->tst == FS_RATE && user_param->test_type == ITERATIONS) {
		ALLOC(user_param->tcompleted, cycles_t, tarr_size);
		memset(user_param->tcompleted, 0, sizeof(cycles_t) * tarr_size);
	}

	if (user_param->machine == CLIENT || user_param->tst == LAT || user_param->duplex) {

		ALLOC(ctx->sge_list, struct ibv_sge,user_param->num_of_qps * user_param->post_list);
		ALLOC(ctx->wr, struct ibv_send_wr, user_param->num_of_qps * user_param->post_list);
		ALLOC(ctx->rem_qpn, uint32_t, user_param->num_of_qps);
		if ((user_param->verb == SEND && user_param->connection_type == UD) ||
				user_param->connection_type == DC || user_param->connection_type == SRD) {
			ALLOC(ctx->ah, struct ibv_ah*, user_param->num_of_qps);
		}
	} else if ((user_param->verb == READ || user_param->verb == WRITE || user_param->verb == WRITE_IMM) && user_param->connection_type == SRD) {
		ALLOC(ctx->ah, struct ibv_ah*, user_param->num_of_qps);
	}

	if ((user_param->verb == SEND || user_param->verb == WRITE_IMM) && (user_param->tst == LAT || user_param->machine == SERVER || user_param->duplex)) {
		ALLOC(ctx->recv_sge_list, struct ibv_sge,
			 user_param->num_of_qps * user_param->recv_post_list);
		ALLOC(ctx->rwr, struct ibv_recv_wr,
			 user_param->num_of_qps * user_param->recv_post_list);
		ALLOC(ctx->rx_buffer_addr, uint64_t, user_param->num_of_qps);
	}
	if (user_param->mac_fwd == ON )
		ctx->cycle_buffer = user_param->size * user_param->rx_depth;

	ctx->size = user_param->size;

	num_of_qps_factor = (user_param->mr_per_qp) ? 1 : user_param->num_of_qps;

	/* 【关键】计算缓冲区大小
	 * 这是决定分配多少内存的核心计算
	 *
	 * 计算公式解析：
	 * 1. BUFF_SIZE(size, cycle_buffer): 取消息大小和循环缓冲区的最大值
	 * 2. INC(..., cache_line_size): 向上对齐到缓存行大小（通常 64 字节）
	 *    - 对齐到缓存行可以避免 false sharing，提高性能
	 * 3. * 2: 乘以 2，因为需要发送缓冲区和接收缓冲区
	 *    - 前半部分：发送缓冲区（CLIENT 用于 RDMA WRITE 的源数据）
	 *    - 后半部分：接收缓冲区（SERVER 用于接收 RDMA WRITE 的目标内存）
	 * 4. * num_of_qps_factor: 根据 QP 数量调整
	 * 5. * flows: 根据流数量调整
	 *
	 * 示例（-s 64K 参数）：
	 * - user_param->size = 65536 字节（64KB）
	 * - 对齐到 64 字节后 = 65536
	 * - * 2（发送+接收）= 131072 字节
	 * - 如果有多个 QP 或 flows，还会进一步扩大
	 */
	fprintf(stderr, "[DEBUG] alloc_ctx [%s]: Calculating buffer size...\n",
		user_param->machine == SERVER ? "SERVER" : "CLIENT");
	fprintf(stderr, "[DEBUG]   - Message size (-s): %lu bytes\n", user_param->size);
	fprintf(stderr, "[DEBUG]   - Cache line size: %d bytes\n", ctx->cache_line_size);
	fprintf(stderr, "[DEBUG]   - Number of QPs: %d\n", user_param->num_of_qps);

	ctx->buff_size = INC(BUFF_SIZE(ctx->size, ctx->cycle_buffer),
				 ctx->cache_line_size) * 2 * num_of_qps_factor * user_param->flows;
	ctx->send_qp_buff_size = ctx->buff_size / num_of_qps_factor / 2;
	ctx->flow_buff_size = ctx->send_qp_buff_size / user_param->flows;
	user_param->buff_size = ctx->buff_size;
	if (user_param->connection_type == UD)
		ctx->buff_size += ctx->cache_line_size;

	fprintf(stderr, "[DEBUG]   - Calculated total buffer size: %lu bytes (%.2f KB)\n",
		ctx->buff_size, ctx->buff_size / 1024.0);

	/* 【关键】实际分配内存缓冲区
	 * memory_create 是一个函数指针回调，根据不同的内存类型调用不同的分配函数：
	 * - host_memory_create(): 标准主机内存（最常见）
	 *   - 使用 memalign() 或 posix_memalign() 分配对齐内存
	 *   - 或者使用 hugepages (2MB 大页) 提高性能
	 * - cuda_memory_create(): GPU 设备内存（CUDA）
	 * - rocm_memory_create(): GPU 设备内存（ROCm）
	 * - 等等...
	 *
	 * 分配流程（以 host_memory_create 为例）：
	 * 1. 创建 memory_ctx 对象
	 * 2. 设置回调函数指针（init, allocate_buffer, free_buffer, copy 等）
	 * 3. 后续调用 memory->allocate_buffer() 分配实际的物理内存
	 * 4. 分配的内存地址会保存到 ctx->buf[i]
	 * 5. 然后调用 ibv_reg_mr() 注册为 MR，使 RDMA 硬件可以访问
	 *
	 * 在 RDMA WRITE 测试中：
	 * - CLIENT: 分配源数据缓冲区，将从这里读取数据执行 RDMA WRITE
	 * - SERVER: 分配目标内存缓冲区，CLIENT 的 RDMA WRITE 会直接写入这里
	 *           SERVER 的 CPU 完全不参与数据传输过程（零拷贝）
	 */
	fprintf(stderr, "[DEBUG] alloc_ctx [%s]: Allocating physical memory via memory_create callback...\n",
		user_param->machine == SERVER ? "SERVER" : "CLIENT");
	fprintf(stderr, "[DEBUG]   - Memory type: %s\n",
		user_param->memory_type == MEMORY_HOST ? "HOST" :
		user_param->memory_type == MEMORY_CUDA ? "CUDA" :
		user_param->memory_type == MEMORY_ROCM ? "ROCm" : "OTHER");

	ctx->memory = user_param->memory_create(user_param);

	if (ctx->memory == NULL) {
		fprintf(stderr, "[ERROR] alloc_ctx [%s]: Failed to create memory context!\n",
			user_param->machine == SERVER ? "SERVER" : "CLIENT");
		return FAILURE;
	}

	fprintf(stderr, "[DEBUG] alloc_ctx [%s]: Memory allocation completed successfully\n",
		user_param->machine == SERVER ? "SERVER" : "CLIENT");
	fprintf(stderr, "[DEBUG]   - Total allocated: %lu bytes (%.2f KB, %.2f MB)\n",
		ctx->buff_size, ctx->buff_size / 1024.0, ctx->buff_size / (1024.0 * 1024.0));

	return SUCCESS;
}
/******************************************************************************
 *
 ******************************************************************************/
void dealloc_ctx(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{

	if (user_param->port_by_qp != NULL)
		free(user_param->port_by_qp);

	if (user_param->tposted != NULL)
		free(user_param->tposted);

	if (((user_param->tst == LAT || user_param->tst == FS_RATE) && user_param->test_type == DURATION) ||
		((user_param->tst == BW || user_param->tst == LAT_BY_BW) && (user_param->machine == CLIENT || user_param->duplex)) ||
		((user_param->tst == BW || user_param->tst == LAT_BY_BW) && user_param->verb == SEND && user_param->machine == SERVER) ||
		(user_param->tst == FS_RATE && user_param->test_type == ITERATIONS))
		if (user_param->tcompleted != NULL)
			free(user_param->tcompleted);

	if (ctx->qp != NULL)
		free(ctx->qp);

	#ifdef HAVE_IBV_WR_API
	if (ctx->qpx != NULL)
		free(ctx->qpx);
	#ifdef HAVE_MLX5DV
	if (ctx->dv_qp != NULL)
		free(ctx->dv_qp);
	if (ctx->mkey != NULL)
		free(ctx->mkey);
	#endif
	if (ctx->r_dctn != NULL)
		free(ctx->r_dctn);
	#ifdef HAVE_DCS
	if (ctx->dci_stream_id != NULL)
		free(ctx->dci_stream_id);
	#endif
	#ifdef HAVE_AES_XTS
	if (ctx->dek != NULL)
		free(ctx->dek);
	#endif
	#ifdef HAVE_SIG_OFFLOAD
	if (ctx->domain != NULL)
		free(ctx->domain);
	if (ctx->t10dif_sig != NULL)
		free(ctx->t10dif_sig);
	#endif
	#endif
	if (ctx->mr != NULL)
		free(ctx->mr);
	if (ctx->buf != NULL)
		free(ctx->buf);
	if ((user_param->tst == BW || user_param->tst == LAT_BY_BW) && (user_param->machine == CLIENT || user_param->duplex)) {
		if (ctx->my_addr != NULL)
			free(ctx->my_addr);
		if (ctx->rem_addr != NULL)
			free(ctx->rem_addr);
		if (ctx->scnt != NULL)
			free(ctx->scnt);
		if (ctx->ccnt != NULL)
			free(ctx->ccnt);

	} else if ((user_param->tst == BW || user_param->tst == LAT_BY_BW)
		   && user_param->verb == SEND && user_param->machine == SERVER) {
		if (ctx->my_addr != NULL)
			free(ctx->my_addr);
	}

	if (user_param->machine == CLIENT || user_param->tst == LAT || user_param->duplex) {
		if (ctx->sge_list != NULL)
			free(ctx->sge_list);
		if (ctx->wr != NULL)
			free(ctx->wr);
		if (ctx->rem_qpn != NULL)
			free(ctx->rem_qpn);

		if ((user_param->verb == SEND && user_param->connection_type == UD) ||
				user_param->connection_type == DC || user_param->connection_type == SRD) {
		if (ctx->ah != NULL)
			free(ctx->ah);
		}
	} else if ((user_param->verb == READ || user_param->verb == WRITE || user_param->verb == WRITE_IMM) && user_param->connection_type == SRD) {
		if (ctx->ah != NULL)
			free(ctx->ah);
	}

	if ((user_param->verb == SEND || user_param->verb == WRITE_IMM) && (user_param->tst == LAT || user_param->machine == SERVER || user_param->duplex)) {
		if (ctx->recv_sge_list != NULL)
			free(ctx->recv_sge_list);
		if (ctx->rwr != NULL)
			free(ctx->rwr);
		if (ctx->rx_buffer_addr != NULL)
			free(ctx->rx_buffer_addr);
	}

	if (ctx->memory != NULL) {
		ctx->memory->destroy(ctx->memory);
		ctx->memory = NULL;
	}
}

/******************************************************************************
 *
 ******************************************************************************/
int destroy_ctx(struct pingpong_context *ctx,
		struct perftest_parameters *user_param)
{
	int i, dereg_counter, rc;
	int test_result = 0;
	int num_of_qps = user_param->num_of_qps;
	int dct_only = (user_param->machine == SERVER && !(user_param->duplex || user_param->tst == LAT));

	if (user_param->wait_destroy) {
		printf(" Waiting %u seconds before releasing resources...\n",
		       user_param->wait_destroy);
		sleep(user_param->wait_destroy);
	}

	dereg_counter = (user_param->mr_per_qp) ? user_param->num_of_qps : 1;

	if (user_param->work_rdma_cm == ON) {
		rc = rdma_cm_disconnect_nodes(ctx, user_param);
		if (rc) {
			fprintf(stderr, "Failed to disconnect RDMA CM nodes.\n");
		}
		rdma_cm_destroy_qps(ctx, user_param);
	}

	if (user_param->work_rdma_cm == ON)
		rdma_disconnect(ctx->cm_id);

	/* in dc with bidirectional,
	 * there are send qps and recv qps. the actual number of send/recv qps
	 * is num_of_qps / 2.
	 */
	if (user_param->duplex || user_param->tst == LAT) {
		num_of_qps /= 2;
	}

	for (i = 0; i < user_param->num_of_qps; i++) {

		if ((((user_param->connection_type == DC && !((!(user_param->duplex || user_param->tst == LAT) && user_param->machine == SERVER)
							|| ((user_param->duplex || user_param->tst == LAT) && i >= num_of_qps))) ||
					user_param->connection_type == UD || user_param->connection_type == SRD) &&
				(user_param->tst == LAT || user_param->machine == CLIENT || user_param->duplex)) ||
				(user_param->connection_type == SRD && (user_param->verb == READ || user_param->verb == WRITE || user_param->verb == WRITE_IMM))) {

			if (user_param->ah_allocated == 1 && ibv_destroy_ah(ctx->ah[i])) {
				fprintf(stderr, "Failed to destroy AH\n");
				test_result = 1;
			}
		}
		if (user_param->work_rdma_cm == OFF) {
			if (ibv_destroy_qp(ctx->qp[i])) {
				fprintf(stderr, "Couldn't destroy QP - %s\n", strerror(errno));
				test_result = 1;
			}
		}
	}

	if (user_param->srq_exists) {
		if (ibv_destroy_srq(ctx->srq)) {
			fprintf(stderr, "Couldn't destroy SRQ\n");
			test_result = 1;
		}
	}

	#ifdef HAVE_XRCD
	if (user_param->use_xrc) {

		if (ibv_close_xrcd(ctx->xrc_domain)) {
			fprintf(stderr, "Couldn't destroy XRC domain\n");
			test_result = 1;
		}

		if (ctx->fd >= 0 && close(ctx->fd)) {
			fprintf(stderr, "Couldn't close the file for the XRC Domain\n");
			test_result = 1;
		}

	}
	#endif

	if (ibv_destroy_cq(ctx->send_cq)) {
		fprintf(stderr, "Failed to destroy CQ - %s\n", strerror(errno));
		test_result = 1;
	}

	if ((user_param->verb == SEND || user_param->verb == WRITE_IMM) || (user_param->connection_type == DC && !dct_only)){
		if (ibv_destroy_cq(ctx->recv_cq)) {
				fprintf(stderr, "Failed to destroy CQ - %s\n", strerror(errno));
				test_result = 1;
			}
	}

	for (i = 0; i < dereg_counter; i++) {
		if (ibv_dereg_mr(ctx->mr[i])) {
			fprintf(stderr, "Failed to deregister MR #%d\n", i+1);
			test_result = 1;
		}
	}

	if (ctx->send_rcredit) {
		if (ibv_dereg_mr(ctx->credit_mr)) {
			fprintf(stderr, "Failed to deregister send credit MR\n");
			test_result = 1;
		}
		free(ctx->ctrl_buf);
		free(ctx->ctrl_sge_list);
		free(ctx->ctrl_wr);
	}

	#ifdef HAVE_REG_MR_EX
	if(ctx->dmah) {
		if (ibv_dealloc_dmah(ctx->dmah)) {
			fprintf(stderr, "Failed to deallocate DMAH - %s\n", strerror(errno));
			test_result = 1;
		}
	}
	#endif

	#ifdef HAVE_AES_XTS
	if(user_param->aes_xts){
		for(i = 0; i < user_param->data_enc_keys_number; i++) {
			if (mlx5dv_dek_destroy(ctx->dek[i]))
				fprintf(stderr, "Failed to destroy data encryption key.\n");
		}

		for(i = 0; i < user_param->num_of_qps; i++) {
			if (mlx5dv_destroy_mkey(ctx->mkey[i]))
				fprintf(stderr, "Failed to destroy MKey.\n");
		}
	}
	#endif

	#ifdef HAVE_SIG_OFFLOAD
	if(user_param->sig_offload){
		for(i = 0; i < user_param->num_of_qps; i++) {
			if (mlx5dv_destroy_mkey(ctx->mkey[i]))
				fprintf(stderr, "Failed to destroy MKey.\n");
		}
	}
	#endif

	#ifdef HAVE_TD_API
	if (user_param->no_lock) {
		if (ibv_dealloc_pd(ctx->pad)) {
			fprintf(stderr, "Failed to deallocate PAD - %s\n", strerror(errno));
			test_result = 1;
		}

		if (ibv_dealloc_td(ctx->td)) {
			fprintf(stderr, "Failed to deallocate TD - %s\n", strerror(errno));
			test_result = 1;
		}
	}
	#endif

	if (ibv_dealloc_pd(ctx->pd)) {
		fprintf(stderr, "Failed to deallocate PD - %s\n", strerror(errno));
		test_result = 1;
	}

	if (ctx->send_channel) {
		if (ibv_destroy_comp_channel(ctx->send_channel)) {
			fprintf(stderr, "Failed to close send event channel\n");
			test_result = 1;
		}
	}

	if (ctx->recv_channel) {
		if (ibv_destroy_comp_channel(ctx->recv_channel)) {
			fprintf(stderr, "Failed to close receive event channel\n");
			test_result = 1;
		}
	}

	if (user_param->use_rdma_cm == OFF) {

		if (ibv_close_device(ctx->context)) {
			fprintf(stderr, "Failed to close device context\n");
			test_result = 1;
		}
	}

	for (i = 0; i < dereg_counter; i++) {
		ctx->memory->free_buffer(ctx->memory, 0, ctx->buf[i], ctx->buff_size);
	}

	free(ctx->qp);
	#ifdef HAVE_IBV_WR_API
	free(ctx->qpx);
	free(ctx->r_dctn);
	#ifdef HAVE_DCS
	free(ctx->dci_stream_id);
	#endif
	#endif
	#ifdef HAVE_AES_XTS
	if(user_param->aes_xts) {
		free(ctx->dek);
		free(ctx->mkey);
	}
	#endif

	if ((user_param->tst == BW || user_param->tst == LAT_BY_BW ) && (user_param->machine == CLIENT || user_param->duplex)) {

		free(user_param->tposted);
		free(user_param->tcompleted);
		free(ctx->my_addr);
		free(ctx->rem_addr);
		free(ctx->scnt);
		free(ctx->ccnt);
	}
	else if ((user_param->tst == BW || user_param->tst == LAT_BY_BW ) && user_param->verb == SEND && user_param->machine == SERVER) {

		free(user_param->tposted);
		free(user_param->tcompleted);
		free(ctx->my_addr);
	}
	if (user_param->machine == CLIENT || user_param->tst == LAT || user_param->duplex) {

		free(ctx->sge_list);
		free(ctx->wr);
	}

	if ((user_param->verb == SEND || user_param->verb == WRITE_IMM) && (user_param->tst == LAT || user_param->machine == SERVER || user_param->duplex)) {

		free(ctx->rx_buffer_addr);
		free(ctx->recv_sge_list);
		free(ctx->rwr);
	}

	if (user_param->work_rdma_cm == ON) {
		rdma_cm_destroy_cma(ctx, user_param);
	}

	if (user_param->counter_ctx) {
		counters_close(user_param->counter_ctx);
	}

	if (ctx->memory != NULL) {
		ctx->memory->destroy(ctx->memory);
		ctx->memory = NULL;
	}

	return test_result;
}

/******************************************************************************
 *
 ******************************************************************************/
#ifdef HAVE_EX_ODP
static int check_odp_transport_caps(struct perftest_parameters *user_param, uint32_t caps)
{
	static char conn_str[][7] = {"RC", "UC", "UD", "RawEth", "XRC", "DC", "SRD"};
	int conn = user_param->connection_type;
	VerbType verb = user_param->verb;
	MachineType machine = user_param->machine;
	int duplex = user_param->duplex;

	if (verb == SEND && duplex == OFF && machine == CLIENT) {
		if (!(caps & IBV_ODP_SUPPORT_SEND)) {
			fprintf(stderr, " ODP Send is not supported for %s transport.\n", conn_str[conn]);
			return 0;
		}
	} else if (verb == SEND && duplex == OFF && machine == SERVER) {
		if (!(caps & (IBV_ODP_SUPPORT_RECV | IBV_ODP_SUPPORT_SRQ_RECV))) {
			fprintf(stderr, " ODP Recv is not supported for %s transport.\n", conn_str[conn]);
			return 0;
		}
	} else if (verb == SEND && duplex == ON) {
		if (!(caps & IBV_ODP_SUPPORT_SEND &&
		      caps & (IBV_ODP_SUPPORT_RECV | IBV_ODP_SUPPORT_SRQ_RECV))) {
			fprintf(stderr, " ODP bidirectional Send is not supported for %s transport.\n", conn_str[conn]);
			return 0;
		}
	} else if ((verb == WRITE || verb == WRITE_IMM) && !(caps & IBV_ODP_SUPPORT_WRITE)) {
		fprintf(stderr, " ODP Write is not supported for %s transport.\n", conn_str[conn]);
		return 0;
	} else if (verb == READ && !(caps & IBV_ODP_SUPPORT_READ)) {
		fprintf(stderr, " ODP Read is not supported for %s transport.\n", conn_str[conn]);
		return 0;
	} else if (verb == ATOMIC && !(caps & IBV_ODP_SUPPORT_ATOMIC)) {
		fprintf(stderr, " ODP Atomics are not supported for %s transport.\n", conn_str[conn]);
		return 0;
	}

	return 1;
}

static int check_odp_support(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	struct ibv_device_attr_ex dattr;
	int conn = user_param->connection_type;
	int ret = ibv_query_device_ex(ctx->context, NULL, &dattr);

	if (ret) {
		fprintf(stderr, " Couldn't query device for On-Demand Paging capabilities.\n");
		return 0;
	}

	/* These capabilities must be set by device drivers. */
	if (!(dattr.odp_caps.general_caps & IBV_ODP_SUPPORT)) {
		fprintf(stderr, " The device does not support On-Demand Paging.\n");
		return 0;
	}

	switch (conn) {
	case RC:
		if ( !check_odp_transport_caps(user_param,
					       dattr.odp_caps.per_transport_caps.rc_odp_caps) )
			return 0;
		break;

	case UC:
		fprintf(stderr," ODP is not available on UC transport.\n");
		return 0;

	case UD:
		/* Checking UD caps is problematic for some devices because UD recive supports ODP from NIC
		* perspective but capabilaties are registered as off, so let's skip checking them. */
		break;

	case XRC:
		if ( !check_odp_transport_caps(user_param, dattr.xrc_odp_caps) )
			return 0;
		break;

	case DC:
		/* A Dynamically Connected transport service is specific to mlx5 devices.
		 * ODP is available, but the device driver does not register the capabilities,
		 * so we cannot get them with ibv_query_device_ex(). They are configured in
		 * libmlx5 and can be gained with an experimental API ibv_exp_query_device(),
		 * but we should stick to generic functions, so let's skip checking them. */
		break;

	case SRD:
		/* Scalable Reliable Datagram is Ethernet-based transport protocol specific to
		 * AWS Elastic Fabric Adapter. ODP is not implemented. */
		fprintf(stderr, " ODP is not available on SRD transport.\n");
		return 0;

	default:
		fprintf(stderr, " Unsupported connection type.\n");
		return 0;
	}

	return 1;
}
#endif

/******************************************************************************
 *
 ******************************************************************************/
static uint32_t get_device_vendor(struct ibv_context *context)
{
	struct ibv_device_attr device_attr;
	memset(&device_attr, 0, sizeof(device_attr));

	if (ibv_query_device(context, &device_attr)) {
		fprintf(stderr, "Failed to query device vendor id\n");
		return 1;
	}

	return device_attr.vendor_id;
}

/******************************************************************************
 *
 ******************************************************************************/
static int is_sig_offload_supported(struct ibv_context *ibv_ctx)
{
	uint32_t is_mlnx_device = get_device_vendor(ibv_ctx) == MLNX_VENDOR_ID;

	if (!is_mlnx_device)
		return 0;

	struct mlx5dv_context ctx = {
		.comp_mask = MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD,
	};

	if (mlx5dv_query_device(ibv_ctx, &ctx)) {
		fprintf(stderr, "Failed to query device capabilities\n");
		return 0;
	}

	if (!(ctx.sig_caps.t10dif_bg & MLX5DV_SIG_T10DIF_BG_CAP_CRC))
		return 0;

	return 1;
}

/******************************************************************************
 *
 ******************************************************************************/

int create_reg_cqs(struct pingpong_context *ctx,
		   struct perftest_parameters *user_param,
		   int tx_buffer_depth, int need_recv_cq)
{
#ifdef HAVE_CQ_EX
	struct ibv_cq_init_attr_ex send_cq_attr = {
		.cqe = tx_buffer_depth * user_param->num_of_qps,
		.cq_context = NULL,
		.channel = ctx->send_channel,
		.comp_vector = user_param->eq_num,
	};

	#ifdef HAVE_TD_API
	if (user_param->no_lock) {
		send_cq_attr.parent_domain = ctx->pad;
		send_cq_attr.comp_mask = IBV_CQ_INIT_ATTR_MASK_PD;
	}
	#endif
	ctx->send_cq = ibv_cq_ex_to_cq(ibv_create_cq_ex(ctx->context, &send_cq_attr));
	if (!ctx->send_cq) {
		if (!user_param->no_lock && errno == EOPNOTSUPP)
			goto cq_ex_not_supported;
		fprintf(stderr, "Couldn't create CQ\n");
		return FAILURE;
	}

	if (need_recv_cq) {
		struct ibv_cq_init_attr_ex recv_cq_attr = {
			.cqe = user_param->rx_depth * user_param->num_of_qps,
			.cq_context = NULL,
			.channel = ctx->recv_channel,
			.comp_vector = user_param->eq_num,
		};
		#ifdef HAVE_TD_API
		if (user_param->no_lock) {
			recv_cq_attr.parent_domain = ctx->pad;
			recv_cq_attr.comp_mask = IBV_CQ_INIT_ATTR_MASK_PD;
		}
		#endif
		ctx->recv_cq = ibv_cq_ex_to_cq(ibv_create_cq_ex(ctx->context, &recv_cq_attr));
		if (!ctx->recv_cq) {
			fprintf(stderr, "Couldn't create a receiver CQ\n");
			return FAILURE;
		}
	}
	return SUCCESS;

cq_ex_not_supported:
#endif
	ctx->send_cq = ibv_create_cq(ctx->context,tx_buffer_depth *
					user_param->num_of_qps, NULL, ctx->send_channel, user_param->eq_num);
	if (!ctx->send_cq) {
		fprintf(stderr, "Couldn't create CQ\n");
		return FAILURE;
	}

	if (need_recv_cq) {
		ctx->recv_cq = ibv_create_cq(ctx->context,user_param->rx_depth *
						user_param->num_of_qps, NULL, ctx->recv_channel, user_param->eq_num);
		if (!ctx->recv_cq) {
			fprintf(stderr, "Couldn't create a receiver CQ\n");
			return FAILURE;
		}
	}

	return SUCCESS;
}

/******************************************************************************
 *
 ******************************************************************************/
int create_cqs(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	int ret;
	int dct_only = 0, need_recv_cq = 0;
	int tx_buffer_depth = user_param->tx_depth;

	if (user_param->connection_type == DC) {
		dct_only = (user_param->machine == SERVER && !(user_param->duplex || user_param->tst == LAT));
	}

	if (dct_only)
		tx_buffer_depth = user_param->rx_depth;

	if ((user_param->connection_type == DC && !dct_only) || (user_param->verb == SEND || user_param->verb == WRITE_IMM))
		need_recv_cq = 1;

	ret = create_reg_cqs(ctx, user_param, tx_buffer_depth, need_recv_cq);

	return ret;
}

/******************************************************************************
 *
 ******************************************************************************/
static int setup_mr_flags(struct perftest_parameters *user_param)
{
	int flags = IBV_ACCESS_LOCAL_WRITE;

	#ifdef HAVE_EX_ODP
	if (user_param->use_odp) {
		flags |= IBV_ACCESS_ON_DEMAND;
	}
	#endif

	if (user_param->verb == WRITE || user_param->verb == WRITE_IMM) {
		flags |= IBV_ACCESS_REMOTE_WRITE;
	} else if (user_param->verb == READ) {
		flags |= IBV_ACCESS_REMOTE_READ;
		if (user_param->transport_type == IBV_TRANSPORT_IWARP)
			flags |= IBV_ACCESS_REMOTE_WRITE;
	} else if (user_param->verb == ATOMIC) {
		flags |= IBV_ACCESS_REMOTE_ATOMIC;
	}

#ifdef HAVE_RO
	if (user_param->disable_pcir == 0) {
		flags |= IBV_ACCESS_RELAXED_ORDERING;
	}
#endif

	return flags;
}

static void initialize_buffer_content(struct pingpong_context *ctx,
				      struct perftest_parameters *user_param,
				      int qp_index, bool can_init_mem)
{
	if (!can_init_mem)
		return;

	uint32_t rng_state = init_perftest_rand_state();
	if ((user_param->verb == WRITE || user_param->verb == WRITE_IMM) && user_param->tst == LAT) {
		memset(ctx->buf[qp_index], 0, ctx->buff_size);
	} else {
		uint64_t i;
		if (user_param->has_payload_modification) {
			for (i = 0; i < ctx->buff_size; i++) {
				((char*)ctx->buf[qp_index])[i] = user_param->payload_content[i % user_param->payload_length];
			}
		} else {
			uint32_t *buf_ptr = (uint32_t*)ctx->buf[qp_index];
			for (i = 0; i < ctx->buff_size/4; i++) {
				buf_ptr[i] = perftest_rand(&rng_state);
			}
		}
	}
}

#ifdef HAVE_REG_MR_EX
static struct ibv_mr *register_mr_ex(struct pingpong_context *ctx, 
				     struct perftest_parameters *user_param,
				     int qp_index, int flags, int dmabuf_fd, 
				     uint64_t dmabuf_offset)
{
	struct ibv_mr_init_attr in = {};
	in.access = flags;
	in.length = ctx->buff_size;

	if (dmabuf_fd) {
		/* DMABUF case: use FD, IOVA and FD_OFFSET instead of ADDR */
		in.comp_mask = IBV_REG_MR_MASK_FD | IBV_REG_MR_MASK_IOVA | IBV_REG_MR_MASK_FD_OFFSET;
		in.fd = dmabuf_fd;
		in.iova = (uint64_t)ctx->buf[qp_index];
		in.fd_offset = dmabuf_offset;
		printf("Calling ibv_reg_mr_ex with dmabuf(offset=%lu, size=%lu, addr=%p, fd=%d) for QP #%d\n",
			   dmabuf_offset, ctx->buff_size, ctx->buf[qp_index], dmabuf_fd, qp_index);
	} else {
		in.comp_mask = IBV_REG_MR_MASK_ADDR;
		in.addr = ctx->buf[qp_index];
	}

	if (user_param->processing_hints != -1) {
		/* Add DMAH mask for TPH support */
		in.comp_mask |= IBV_REG_MR_MASK_DMAH;
		in.dmah = ctx->dmah;
	}

	return ibv_reg_mr_ex(ctx->pd, &in);
}
#endif

/* register_mr 函数: 注册内存区域（Memory Region, MR）
 * MR 注册是 RDMA 操作的核心步骤，使内存可以被 RDMA 硬件访问
 *
 * 参数说明：
 * - ctx: RDMA 上下文，包含 PD 和缓冲区
 * - user_param: 用户配置参数
 * - qp_index: QP 索引，用于定位对应的缓冲区
 * - flags: 访问权限标志（LOCAL_WRITE, REMOTE_WRITE, REMOTE_READ 等）
 * - dmabuf_fd: DMA-BUF 文件描述符（GPU 内存等特殊情况）
 * - dmabuf_offset: DMA-BUF 偏移量
 *
 * 返回值：
 * - 成功返回 ibv_mr 指针，包含 lkey 和 rkey
 * - lkey: 本地访问密钥，用于本地 RDMA 操作
 * - rkey: 远程访问密钥，需要传递给对端用于 RDMA WRITE/READ
 */
static struct ibv_mr *register_mr(struct pingpong_context *ctx,
				   struct perftest_parameters *user_param,
				   int qp_index, int flags, int dmabuf_fd,
				   uint64_t dmabuf_offset)
{
	/* 判断是否使用 DMABUF（GPU 内存或其他设备内存） */
	if (dmabuf_fd) {
#ifdef HAVE_REG_DMABUF_MR
		/* DMABUF registration using standard API */
#ifdef HAVE_DATA_DIRECT
		if (user_param->use_data_direct) {
			printf("Calling mlx5dv_reg_dmabuf_mr(offset=%lu, size=%lu, addr=%p, fd=%d) for QP #%d\n",
					dmabuf_offset, ctx->buff_size, ctx->buf[qp_index], dmabuf_fd, qp_index);
			return mlx5dv_reg_dmabuf_mr(
				ctx->pd, dmabuf_offset,
				ctx->buff_size, (uint64_t)ctx->buf[qp_index],
				dmabuf_fd,
				flags, MLX5DV_REG_DMABUF_ACCESS_DATA_DIRECT
				);
		} else
#endif
		{
			printf("Calling ibv_reg_dmabuf_mr(offset=%lu, size=%lu, addr=%p, fd=%d) for QP #%d\n",
				   dmabuf_offset, ctx->buff_size, ctx->buf[qp_index], dmabuf_fd, qp_index);
			return ibv_reg_dmabuf_mr(
				ctx->pd, dmabuf_offset,
				ctx->buff_size, (uint64_t)ctx->buf[qp_index],
				dmabuf_fd,
				flags
				);
		}
#else
		fprintf(stderr, "DMABUF requested but not supported in this build\n");
		return NULL;
#endif
	} else {
		/* 标准内存注册流程（最常见的情况）
		 * ibv_reg_mr 是 RDMA 核心 API，向 NIC 注册一段内存
		 *
		 * 参数：
		 * - ctx->pd: Protection Domain，内存保护域
		 * - ctx->buf[qp_index]: 要注册的内存起始地址
		 * - ctx->buff_size: 内存区域大小
		 * - flags: 访问权限标志
		 *
		 * 在 RDMA WRITE 场景中：
		 * - CLIENT: 注册本地内存用于发送数据（需要 LOCAL_WRITE 权限）
		 * - SERVER: 注册远程内存供 CLIENT 写入（需要 REMOTE_WRITE 权限）
		 *           SERVER 的 rkey 会通过参数交换发送给 CLIENT
		 *           CLIENT 使用这个 rkey 在 WQE 中指定目标内存
		 */
		fprintf(stderr, "[DEBUG] register_mr [%s]: Registering MR with ibv_reg_mr()\n",
		        user_param->machine == SERVER ? "SERVER" : "CLIENT");
		fprintf(stderr, "[DEBUG] register_mr: addr=%p, size=%lu, flags=0x%x\n",
		        ctx->buf[qp_index], ctx->buff_size, flags);

		return ibv_reg_mr(ctx->pd, ctx->buf[qp_index], ctx->buff_size, flags);
	}
}

/* register_memory_region 函数: MR 注册的统一入口
 * 这是一个包装函数，根据不同的配置选择合适的注册方法
 *
 * MR 注册流程概述：
 * 1. 选择注册函数（标准 API vs 扩展 API）
 * 2. 执行注册操作
 * 3. 保存 MR 指针到 ctx->mr[qp_index]
 * 4. CLIENT 和 SERVER 都需要注册自己的内存
 *
 * 注册成功后：
 * - MR 包含 lkey 和 rkey
 * - CLIENT 需要 SERVER 的 rkey 来执行 RDMA WRITE
 * - 这个 rkey 通过参数交换（ctx_hand_shake）传递
 */
static int register_memory_region(struct pingpong_context *ctx,
				  struct perftest_parameters *user_param,
				  int qp_index, int flags, int dmabuf_fd,
				  uint64_t dmabuf_offset)
{
	struct ibv_mr *mr = NULL;

	/* 定义函数指针：用于选择不同的注册函数 */
	struct ibv_mr *(*register_func)(struct pingpong_context *ctx,
					struct perftest_parameters *user_param,
					int qp_index, int flags, int dmabuf_fd,
					uint64_t dmabuf_offset);

	fprintf(stderr, "[DEBUG] register_memory_region [%s]: Starting MR registration for QP #%d\n",
	        user_param->machine == SERVER ? "SERVER" : "CLIENT", qp_index);

#ifdef HAVE_REG_MR_EX
	/* 优先使用扩展 API（支持 TPH 等高级特性）
	 * 除非使用 data_direct（需要特殊的 mlx5dv_reg_dmabuf_mr）
	 */
	if (!(user_param->use_data_direct && dmabuf_fd)) {
		register_func = register_mr_ex;
		fprintf(stderr, "[DEBUG] register_memory_region: Using extended API (register_mr_ex)\n");
	} else {
		register_func = register_mr;
		fprintf(stderr, "[DEBUG] register_memory_region: Using standard API (register_mr) for data_direct\n");
	}
#else
	/* 没有扩展 API 时使用标准注册方法 */
	register_func = register_mr;
	fprintf(stderr, "[DEBUG] register_memory_region: Using standard API (register_mr)\n");
#endif

	/* 执行 MR 注册 */
	mr = register_func(ctx, user_param, qp_index, flags, dmabuf_fd, dmabuf_offset);

	/* 如果扩展 API 不支持，回退到标准 API */
	if (!mr && (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT) &&
	    register_func != register_mr) {
		fprintf(stderr, "[DEBUG] register_memory_region: Extended API not supported, falling back to standard API\n");
		register_func = register_mr;
		mr = register_func(ctx, user_param, qp_index, flags, dmabuf_fd, dmabuf_offset);
	}

	/* 注册失败处理 */
	if (!mr) {
		fprintf(stderr, "Couldn't allocate MR with error=%d\n", errno);

		if (dmabuf_fd && errno == EOPNOTSUPP) {
			fprintf(stderr, "OFED stack does not support DMA-BUF\n");
			close(dmabuf_fd);
		}

		return FAILURE;
	}

	/* 保存 MR 指针到上下文
	 * 这个 MR 包含：
	 * - lkey: 用于本地 RDMA 操作
	 * - rkey: 用于远程 RDMA 操作（SERVER 的 rkey 需要传给 CLIENT）
	 */
	ctx->mr[qp_index] = mr;
	fprintf(stderr, "[DEBUG] register_memory_region [%s]: MR registered successfully\n",
	        user_param->machine == SERVER ? "SERVER" : "CLIENT");
	fprintf(stderr, "[DEBUG] register_memory_region: lkey=0x%x, rkey=0x%x\n",
	        mr->lkey, mr->rkey);

	/* 清理 DMABUF 文件描述符 */
	if (dmabuf_fd) {
		close(dmabuf_fd);
	}

	return SUCCESS;
}

int create_single_mr(struct pingpong_context *ctx, struct perftest_parameters *user_param, int qp_index)
{
	bool can_init_mem = true;
	int dmabuf_fd = 0;
	uint64_t dmabuf_offset = 0;

	if (user_param->use_odp) {
		if ( !check_odp_support(ctx, user_param) )
			return FAILURE;
	}

	if (user_param->memory_type == MEMORY_MMAP) {
		#if defined(__FreeBSD__)
		posix_memalign(ctx->buf, user_param->cycle_buffer, ctx->buff_size);
		#else
		ctx->buf = memalign(user_param->cycle_buffer, ctx->buff_size);
		#endif
	}

	if (ctx->memory->allocate_buffer(ctx->memory, user_param->cycle_buffer, ctx->buff_size,
						&dmabuf_fd, &dmabuf_offset, &ctx->buf[qp_index],
						&can_init_mem)) {
		return FAILURE;
	}

	/* Setup access flags */
	int flags = setup_mr_flags(user_param);

	/* Register memory region */
	if (register_memory_region(ctx, user_param, qp_index, flags, dmabuf_fd, dmabuf_offset) != SUCCESS) {
		return FAILURE;
	}

	if (user_param->use_null_mr) {
		ctx->null_mr = ibv_alloc_null_mr(ctx->pd);
		if (!ctx->null_mr) {
			fprintf(stderr, "Couldn't create null MR\n");
			return FAILURE;
		}
	}

	/* Initialize buffer content */
	initialize_buffer_content(ctx, user_param, qp_index, can_init_mem);

	return SUCCESS;
}


static int create_payload(struct perftest_parameters *user_param)
{
	char* file_content;
	char* token;
	int payload_file_size;
	int counter = 0;
	FILE* fptr;

	/* read payload text file */
	fptr = fopen(user_param->payload_file_path, "r");
	if (!fptr)
	{
		fprintf(stderr, "Failed to open '%s'\n", user_param->payload_file_path);
		return 1;
	}

	/* get payload file size*/
	fseek(fptr, 0, SEEK_END);
	payload_file_size = ftell(fptr);
	fseek(fptr, 0, SEEK_SET);

	if (payload_file_size <= 0) {
		fprintf(stderr, "Payload size should be greater than 0\n");
		fclose(fptr);
		return 1;
	}

	/* read payload file content*/
	ALLOCATE(file_content, char, payload_file_size + 1);
	if (payload_file_size != fread(file_content, 1, payload_file_size, fptr)) {
		fprintf(stderr, "Failed to read payload file\n");
		free(file_content);
		fclose(fptr);
		return 1;
	}

	file_content[payload_file_size] = '\0';
	/* allocate buffer for the payload*/
	ALLOCATE(user_param->payload_content, char, user_param->size + 1);

	/* get token in DWORD form: '0xaaaaaaaa' */
	token = strtok(file_content, ",");

	do {
			int i;
			char current_byte_chars[2];
			if (strlen(token) != 10) {
				fprintf(stderr, "Failed to parse DWORD number: %d\n", counter/4);
				free(user_param->payload_content);
				free(file_content);
				fclose(fptr);
				return 1;
			}
			for(i = 0; i < 8; i += 2){
				current_byte_chars[0] = token[8-i];
				current_byte_chars[1] = token[9-i];
				if (!isxdigit(current_byte_chars[0]) || !isxdigit(current_byte_chars[1])) {
					fprintf(stderr, "Invalid hex char in DWORD number: %d\n", counter/4);
					free(user_param->payload_content);
					free(file_content);
					fclose(fptr);
					return 1;
				}
				user_param->payload_content[counter] = (char) strtol(current_byte_chars, NULL, 16);

				counter++;
				if (counter == user_param->size)
					break;
			}
		token = strtok(NULL, ",\n");
	} while (token != NULL && counter < user_param->size);

	user_param->payload_content[counter] = '\0';
	user_param->payload_length = counter;
	free(file_content);
	fclose(fptr);

	return 0;
}

/******************************************************************************
 *
 ******************************************************************************/
int create_mr(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	int i;
	int mr_index = 0;

	if (user_param->has_payload_modification){
		if (create_payload(user_param)){
			return 1;
		}
	}

	/* create first MR */
	if (create_single_mr(ctx, user_param, 0)) {
		fprintf(stderr, "failed to create mr\n");
		return 1;
	}
	mr_index++;

	/* create the rest if needed, or copy the first one */
	for (i = 1; i < user_param->num_of_qps; i++) {
		if (user_param->mr_per_qp) {
			if (create_single_mr(ctx, user_param, i)) {
				fprintf(stderr, "failed to create mr\n");
				goto destroy_mr;
			}
			mr_index++;
		} else {
			ctx->mr[i] = ctx->mr[0];
			// cppcheck-suppress arithOperationsOnVoidPointer
			ctx->buf[i] = ctx->buf[0] + (i*BUFF_SIZE(ctx->size, ctx->cycle_buffer));
		}
	}

	return 0;

destroy_mr:
	for (i = 0; i < mr_index; i++)
		ibv_dereg_mr(ctx->mr[i]);

	return FAILURE;
}

#ifdef HAVE_REG_MR_EX
/******************************************************************************
 *
 ******************************************************************************/
int create_dmah(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	struct ibv_dmah_init_attr attr;
	memset(&attr, 0, sizeof(attr));

	if (user_param->processing_hints != -1) {
		attr.ph = user_param->processing_hints;
		attr.comp_mask = IBV_DMAH_INIT_ATTR_MASK_PH;
	}

	if (user_param->tph_mem_type != -1) {
		attr.tph_mem_type = user_param->tph_mem_type;
		attr.comp_mask |= IBV_DMAH_INIT_ATTR_MASK_TPH_MEM_TYPE;
	}

	if (user_param->cpu_id != -1) {
		attr.cpu_id = user_param->cpu_id;
		attr.comp_mask |= IBV_DMAH_INIT_ATTR_MASK_CPU_ID;
	}

	ctx->dmah = ibv_alloc_dmah(ctx->context, &attr);

	if (!ctx->dmah) {
		fprintf(stderr, "Couldn't allocate DMAH: %d\n", errno);
		return FAILURE;
	}

	return SUCCESS;
}
#endif

/******************************************************************************
 *
 ******************************************************************************/
int verify_params_with_device_context(struct ibv_context *context,
				      struct perftest_parameters *user_param)
{
	enum ctx_device current_dev = ib_dev_name(context);
	if(user_param->use_event) {
		if(user_param->eq_num > context->num_comp_vectors) {
			fprintf(stderr, " Completion vector specified is invalid\n");
			fprintf(stderr, " Max completion vector = %d\n",
				context->num_comp_vectors - 1);
			return FAILURE;
		}
	}

	// those are devices supporting new post send
	if (current_dev != CONNECTIB &&
		current_dev != CONNECTX4 &&
		current_dev != CONNECTX4LX &&
		current_dev != CONNECTX5 &&
		current_dev != CONNECTX5EX &&
		current_dev != CONNECTX6 &&
		current_dev != CONNECTX6DX &&
		current_dev != CONNECTX6LX &&
		current_dev != CONNECTX7 &&
		current_dev != CONNECTX8 &&
		current_dev != CONNECTX9 &&
		current_dev != CONNECTX10 &&
		current_dev != MLX5GENVF &&
		current_dev != BLUEFIELD &&
		current_dev != BLUEFIELD2 &&
		current_dev != BLUEFIELD3 &&
		current_dev != EFA &&
		current_dev != HNS &&
		current_dev != YUNSILICON_ANDES &&
		current_dev != YUNSILICON_DIAMOND&&
		current_dev != YUNSILICON_DIAMOND_NEXT)
	{
		if (!user_param->use_old_post_send)
		{
			user_param->use_old_post_send = 1;
		}
	}

	return SUCCESS;
}

#if defined HAVE_OOO_ATTR
static int verify_ooo_settings(struct pingpong_context *ctx,
			       struct perftest_parameters *user_param)
{
	#ifdef HAVE_OOO_ATTR
	struct ibv_device_attr_ex attr = { };
	if (ibv_query_device_ex(ctx->context, NULL, &attr))
	#endif
		return FAILURE;

	if (user_param->connection_type == RC) {
		if (attr.ooo_caps.rc_caps == 0) {
			fprintf(stderr, " OOO unsupported by HCA on RC QP\n");
			return FAILURE;
		} else {
			return SUCCESS;
		}
	} else if (user_param->connection_type == XRC) {
		if (attr.ooo_caps.xrc_caps == 0) {
			fprintf(stderr, " OOO unsupported by HCA on XRC QP\n");
			return FAILURE;
		} else {
			return SUCCESS;
		}
	} else if (user_param->connection_type == UD) {
		if (attr.ooo_caps.ud_caps == 0) {
			fprintf(stderr, " OOO unsupported by HCA on UD QP\n");
			return FAILURE;
		} else {
			return SUCCESS;
		}

	#if HAVE_OOO_ATTR
	} else if (user_param->connection_type == UC) {
		if (attr.ooo_caps.uc_caps == 0) {
			fprintf(stderr, " OOO unsupported by HCA on UC QP\n");
			return FAILURE;
		} else {
			return SUCCESS;
		}
	#endif
	} else {
		return FAILURE;
	}
}
#endif

void check_bf_support(struct pingpong_context *ctx)
{
	if (get_device_vendor(ctx->context) != MLNX_VENDOR_ID)
		return;

	#ifdef HAVE_MLX5DV_BF_FLAG
	struct mlx5dv_context ctx_dv;
	int ret;

	ret = mlx5dv_query_device(ctx->context, &ctx_dv);
	if (ret) {
		fprintf(stderr, "Failed to query device capabilities, ret=%d\n", ret);
		return;
	}
	if (!(ctx_dv.flags & MLX5DV_CONTEXT_FLAGS_BLUEFLAME)) {
		fprintf(stderr, "Warning: Blueflame is not supported in the system\n");
		printf(RESULT_LINE);
	}
	#endif
}

int ctx_init(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	int i;
	int dct_only = (user_param->machine == SERVER && !(user_param->duplex || user_param->tst == LAT));
	int qp_index = 0, dereg_counter;
	#ifdef HAVE_MLX5DV
	int mkey_index = 0, dek_index = 0;
	#endif

	#if defined HAVE_OOO_ATTR
	if (user_param->use_ooo) {
		if (verify_ooo_settings(ctx, user_param) != SUCCESS) {
			fprintf(stderr, "Incompatible OOO settings\n");
			return FAILURE;
		}
	}
	#endif

	/* Allocating event channels if requested. */
	if (user_param->use_event) {
		ctx->send_channel = ibv_create_comp_channel(ctx->context);
		if (!ctx->send_channel) {
			fprintf(stderr, "Couldn't create send completion channel\n");
			return FAILURE;
		}

		ctx->recv_channel = ibv_create_comp_channel(ctx->context);
		if (!ctx->recv_channel) {
			fprintf(stderr, "Couldn't create receive completion channel\n");
			return FAILURE;
		}
	}

	/* Allocating the Protection domain.
	 * PD (Protection Domain) 保护域：
	 * - 作用：隔离不同应用程序的 RDMA 资源
	 * - PD 是 MR (Memory Region) 和 QP (Queue Pair) 的容器
	 * - 同一个 PD 内的 QP 可以访问该 PD 内注册的 MR
	 * - 不同 PD 之间的资源是隔离的，提供安全性
	 * - CLIENT 和 SERVER 各自有自己的 PD
	 */
	fprintf(stderr, "[DEBUG] ctx_init [%s]: Allocating Protection Domain (PD)...\n",
		user_param->machine == SERVER ? "SERVER" : "CLIENT");
	ctx->pd = ibv_alloc_pd(ctx->context);  // 从设备上下文分配 PD
	if (!ctx->pd) {
		fprintf(stderr, "Couldn't allocate PD\n");
		goto comp_channel;
	}
	fprintf(stderr, "[DEBUG] ctx_init [%s]: PD allocated successfully\n",
		user_param->machine == SERVER ? "SERVER" : "CLIENT");

	#ifdef HAVE_TD_API
	/* Allocating the Thread domain, Parent domain. */
	if (user_param->no_lock) {
		struct ibv_td_init_attr td_attr = {0};
		ctx->td = ibv_alloc_td(ctx->context, &td_attr);
		if (!ctx->td) {
			fprintf(stderr, "Couldn't allocate TD\n");
			goto pd;
		}

		struct ibv_parent_domain_init_attr pad_attr = {
			.pd = ctx->pd,
			.td = ctx->td,
			.comp_mask = 0,
		};

		ctx->pad = ibv_alloc_parent_domain(ctx->context, &pad_attr);
		if (!ctx->pad) {
			fprintf(stderr, "Couldn't allocate PAD\n");
			goto td;
		}
	} else {
	#endif
		ctx->pad = ctx->pd;
	#ifdef HAVE_TD_API
	}
	#endif


	#ifdef HAVE_AES_XTS
	if(user_param->aes_xts){
		struct mlx5dv_dek_init_attr dek_attr = {};
		struct mlx5dv_mkey_init_attr mkey_init_attr = {};

		ctx->dek_number = 0;
		dek_attr.key_size = MLX5DV_CRYPTO_KEY_SIZE_128;
		dek_attr.has_keytag = 0;
		dek_attr.key_purpose = MLX5DV_CRYPTO_KEY_PURPOSE_AES_XTS;
		dek_attr.pd = ctx->pd;
		dek_attr.opaque[0] = 0x11;
		mkey_init_attr.pd = ctx->pd;
		mkey_init_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
		MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO;

		mkey_init_attr.max_entries = 1;
		for(i = 0; i < user_param->data_enc_keys_number; i++) {

			if (set_valid_dek(dek_attr.key, user_param)) {
				fprintf(stderr, "Failed to set dek\n");
				goto dek;
			}

			ctx->dek[i] = mlx5dv_dek_create(ctx->context, &dek_attr);

			if(!ctx->dek[i]) {
				fprintf(stderr, "Failed to create dek\n");
				goto dek;
			}

			dek_index++;
		}

		for(i = 0; i < user_param->num_of_qps; i++) {
			ctx->mkey[i] = mlx5dv_create_mkey(&mkey_init_attr);

			if(!ctx->mkey[i]) {
				fprintf(stderr, "Failed to create mkey\n");
				goto mkey;
			}

			mkey_index++;
		}
	}
	#endif

	#ifdef HAVE_SIG_OFFLOAD
	if(user_param->sig_offload){
		struct mlx5dv_mkey_init_attr mkey_init_attr = {};
		mkey_init_attr.pd = ctx->pd;
		mkey_init_attr.max_entries = 1;
		mkey_init_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT |
					MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE;

		if (!is_sig_offload_supported(ctx->context)) {
			fprintf(stderr, "T10DIF signature offload is not supported by the device\n");
			goto mkey;
		}

		for(i = 0; i < user_param->num_of_qps; i++) {
			ctx->mkey[i] = mlx5dv_create_mkey(&mkey_init_attr);

			if(!ctx->mkey[i]) {
				fprintf(stderr, "Failed to create mkey\n");
				goto mkey;
			}

			mkey_index++;
		}

		set_sig_domain(ctx);
	}
	#endif

	if (ctx->memory->init(ctx->memory)) {
		fprintf(stderr, "Failed to init memory\n");
		goto mkey;
	}

	#ifdef HAVE_REG_MR_EX
	if (user_param->tph_mem_type != -1 || user_param->processing_hints != -1) {
		if (create_dmah(ctx, user_param)) {
			fprintf(stderr, "Failed to create DMAH\n");
			goto mkey;
		}
	}
	#endif

	if (create_mr(ctx, user_param)) {
		fprintf(stderr, "Failed to create MR\n");
		goto dmah;
	}

	if (create_cqs(ctx, user_param)) {
		fprintf(stderr, "Failed to create CQs\n");
		goto mr;

	}

	#ifdef HAVE_XRCD
	if (user_param->use_xrc) {

		if (ctx_xrcd_create(ctx,user_param)) {
			fprintf(stderr, "Couldn't create XRC resources\n");
			goto cqs;
		}

		if (ctx_xrc_srq_create(ctx,user_param)) {
			fprintf(stderr, "Couldn't create SRQ XRC resources\n");
			goto xrcd;
		}
	}
	#endif

	if (user_param->use_srq && user_param->connection_type == DC &&
			(user_param->tst == LAT ||
			user_param->machine == SERVER ||
			user_param->duplex == ON))
	{
		struct ibv_srq_init_attr_ex attr;
			memset(&attr, 0, sizeof(attr));
		attr.comp_mask = IBV_SRQ_INIT_ATTR_TYPE | IBV_SRQ_INIT_ATTR_PD;
		attr.attr.max_wr = user_param->rx_depth;
		attr.attr.max_sge = 1;
		attr.pd = ctx->pad;

		attr.srq_type = IBV_SRQT_BASIC;
		ctx->srq = ibv_create_srq_ex(ctx->context, &attr);
		if (!ctx->srq)  {
			fprintf(stderr, "Couldn't create SRQ\n");
			goto xrc_srq;
		}
	}

	if (user_param->use_srq && user_param->connection_type != DC &&
			!user_param->use_xrc && (user_param->tst == LAT ||
			user_param->machine == SERVER || user_param->duplex == ON)) {

		struct ibv_srq_init_attr attr = {
			.attr = {
				/* when using sreq, rx_depth sets the max_wr */
				.max_wr  = user_param->rx_depth,
				.max_sge = 1
			}
		};
		ctx->srq = ibv_create_srq(ctx->pad, &attr);
		if (!ctx->srq)  {
			fprintf(stderr, "Couldn't create SRQ\n");
			goto xrcd;
		}
	}

	/*
	* QPs creation in RDMA CM flow will be done separately.
	* Unless, the function called with RDMA CM connection contexts,
	* need to verify the call with the existence of ctx->cm_id.
	*/
	if (!(user_param->work_rdma_cm == OFF || ctx->cm_id))
		return SUCCESS;

	for (i=0; i < user_param->num_of_qps; i++) {
		if (create_qp_main(ctx, user_param, i)) {
			fprintf(stderr, "Failed to create QP.\n");
			goto qps;
		}

		if (user_param->work_rdma_cm == OFF) {
			modify_qp_to_init(ctx, user_param, i);
		}

		qp_index++;
	}

	return SUCCESS;


qps:
	for(i = 0; i < qp_index; i++){
		ibv_destroy_qp(ctx->qp[i]);
	}

	if (user_param->use_srq && (user_param->tst == LAT ||
			user_param->machine == SERVER || user_param->duplex == ON))
		ibv_destroy_srq(ctx->srq);

xrcd: __attribute__((unused))
	#ifdef HAVE_XRCD
	if (user_param->use_xrc)
		ibv_close_xrcd(ctx->xrc_domain);

xrc_srq:
	if (user_param->use_xrc)
		ibv_destroy_srq(ctx->srq);
	#endif
// cppcheck-suppress unusedLabelConfiguration
cqs:
	ibv_destroy_cq(ctx->send_cq);

	if ((user_param->verb == SEND || user_param->verb == WRITE_IMM) || (user_param->connection_type == DC && !dct_only)){
		ibv_destroy_cq(ctx->recv_cq);
	}

mr:
	dereg_counter = (user_param->mr_per_qp) ? user_param->num_of_qps : 1;

	for (i = 0; i < dereg_counter; i++)
		ibv_dereg_mr(ctx->mr[i]);

dmah:
#ifdef HAVE_REG_MR_EX
	if(ctx->dmah) {
		ibv_dealloc_dmah(ctx->dmah);
	}
#endif

mkey:
	#ifdef HAVE_AES_XTS
	if(user_param->aes_xts)
		for (i = 0; i < mkey_index; i++)
			mlx5dv_destroy_mkey(ctx->mkey[i]);
	#endif
	#ifdef HAVE_SIG_OFFLOAD
	if(user_param->sig_offload)
		for (i = 0; i < mkey_index; i++)
			mlx5dv_destroy_mkey(ctx->mkey[i]);
	#endif

#ifdef HAVE_AES_XTS
dek:
	if(user_param->aes_xts)
		for (i = 0; i < dek_index; i++)
			mlx5dv_dek_destroy(ctx->dek[i]);
#endif

#ifdef HAVE_TD_API
	if (user_param->no_lock)
		ibv_dealloc_pd(ctx->pad);

td:
	if (user_param->no_lock)
		ibv_dealloc_td(ctx->td);
pd:
#endif

	ibv_dealloc_pd(ctx->pd);

comp_channel:
	if (user_param->use_event) {
		ibv_destroy_comp_channel(ctx->send_channel);
		ibv_destroy_comp_channel(ctx->recv_channel);
	}

	return FAILURE;
}

int modify_qp_to_init(struct pingpong_context *ctx,
		struct perftest_parameters *user_param, int qp_index)
{
	if (ctx_modify_qp_to_init(ctx->qp[qp_index], user_param,
		qp_index)) {
		fprintf(stderr, "Failed to modify QP to INIT\n");
		return FAILURE;
	}

	return SUCCESS;
}

/******************************************************************************
 *
 ******************************************************************************/
int create_reg_qp_main(struct pingpong_context *ctx,
				struct perftest_parameters *user_param,
				int i)
{
	if (user_param->use_xrc) {
		#ifdef HAVE_XRCD
		ctx->qp[i] = ctx_xrc_qp_create(ctx, user_param, i);
		#endif
	} else {
		ctx->qp[i] = ctx_qp_create(ctx, user_param, i);
	}

	if (ctx->qp[i] == NULL) {
		fprintf(stderr, "Unable to create QP.\n");
		return FAILURE;
	}
	#ifdef HAVE_IBV_WR_API
	if (!user_param->use_old_post_send) {
		ctx->qpx[i] = ibv_qp_to_qp_ex(ctx->qp[i]);
		#ifdef HAVE_MLX5DV
		if (user_param->connection_type == DC)
		{
			ctx->dv_qp[i] = mlx5dv_qp_ex_from_ibv_qp_ex(ctx->qpx[i]);
		}
		#ifdef HAVE_AES_XTS
		if (user_param->aes_xts){
			ctx->dv_qp[i] = mlx5dv_qp_ex_from_ibv_qp_ex(ctx->qpx[i]);
		}
		#endif
		#ifdef HAVE_SIG_OFFLOAD
		if (user_param->sig_offload) {
			ctx->dv_qp[i] = mlx5dv_qp_ex_from_ibv_qp_ex(ctx->qpx[i]);
		}
		#endif
		#endif
	}
	#endif

	return SUCCESS;
}

int create_qp_main(struct pingpong_context *ctx,
		struct perftest_parameters *user_param, int i)
{
	int ret;
	ret = create_reg_qp_main(ctx, user_param, i);
	return ret;
}

/* ctx_qp_create 函数: 创建 Queue Pair (QP)
 *
 * QP 是 RDMA 通信的核心，相当于 socket 连接的端点
 *
 * QP 包含两个队列：
 * - Send Queue (SQ): 发送工作请求 (WR) 队列
 * - Receive Queue (RQ): 接收工作请求 (WR) 队列
 *
 * 在 RDMA WRITE 测试中：
 * - CLIENT: 需要 SQ 来 post RDMA WRITE 请求，不需要 RQ（单边操作）
 * - SERVER: 实际上两个队列都不主动使用（被动接收，硬件处理）
 *
 * 使用 RDMA CM (-R 参数) 时：
 * - QP 通过 rdma_create_qp() 创建，并自动绑定到 rdma_cm_id
 * - RDMA CM 会自动管理 QP 状态转换 (INIT → RTR → RTS)
 */
struct ibv_qp* ctx_qp_create(struct pingpong_context *ctx,
		struct perftest_parameters *user_param, int qp_index)
{
	struct ibv_qp* qp = NULL;
	int dc_num_of_qps = user_param->num_of_qps / 2;

	int is_dc_server_side = 0;
	struct ibv_qp_init_attr attr;
	memset(&attr, 0, sizeof(struct ibv_qp_init_attr));
	struct ibv_qp_cap *qp_cap = &attr.cap;

	fprintf(stderr, "[DEBUG] ctx_qp_create [%s]: Creating QP #%d\n",
		user_param->machine == SERVER ? "SERVER" : "CLIENT", qp_index);

	#ifdef HAVE_IBV_WR_API
	enum ibv_wr_opcode opcode;
	struct ibv_qp_init_attr_ex attr_ex;
	memset(&attr_ex, 0, sizeof(struct ibv_qp_init_attr_ex));
	#ifdef HAVE_MLX5DV
	struct mlx5dv_qp_init_attr attr_dv;
	memset(&attr_dv, 0, sizeof(attr_dv));
	#ifdef HAVE_OOO_RECV_WRS
	struct mlx5dv_context ctx_dv;
	uint32_t is_mlnx_device;
	memset(&ctx_dv, 0, sizeof(ctx_dv));
	#endif
	#endif
	#ifdef HAVE_SRD
	struct efadv_qp_init_attr efa_attr = {};
	#endif
	#endif
	#ifdef HAVE_HNSDV
	struct hnsdv_qp_init_attr hns_attr = {};
	#endif

	/* 配置 Completion Queue (CQ)
	 * - send_cq: 发送完成队列，所有 QP 都需要
	 * - recv_cq: 接收完成队列，取决于操作类型：
	 *   * SEND/WRITE_IMM: 需要独立的 recv_cq（接收端需要 poll）
	 *   * WRITE/READ: 使用 send_cq（单边操作，接收端不需要 poll）
	 *
	 * 在 RDMA WRITE 测试中：
	 * - CLIENT: 只需要 poll send_cq（检查 WRITE 完成）
	 * - SERVER: 不需要 poll 任何 CQ（被动接收，硬件处理）
	 */
	attr.send_cq = ctx->send_cq;
	attr.recv_cq = (user_param->verb == SEND || user_param->verb == WRITE_IMM) ? ctx->recv_cq : ctx->send_cq;
	fprintf(stderr, "[DEBUG] ctx_qp_create: CQ assignment - send_cq=%p, recv_cq=%p\n",
		attr.send_cq, attr.recv_cq);

	is_dc_server_side = ((!(user_param->duplex || user_param->tst == LAT) &&
						  (user_param->machine == SERVER)) ||
						 ((user_param->duplex || user_param->tst == LAT) &&
						  (qp_index >= dc_num_of_qps)));

	/* 配置 QP 容量参数（Capacity）
	 * - max_inline_data: 内联数据大小（数据直接放入 WQE，不需要 MR）
	 *   * 来源：-I 参数或自动计算（user_param->inline_size）
	 * - max_send_wr: 发送队列深度（Send Queue Depth）
	 *   * 来源：-t 参数，默认 128（write_bw）
	 *   * CLIENT 会循环 post 这么多 WQE 后再 poll
	 * - max_send_sge: 发送 Scatter-Gather Entry 数量
	 *   * 每个 WQE 可以包含多个内存片段
	 *   * 默认 MAX_SEND_SGE (通常为 1)
	 *
	 * 在 RDMA WRITE 测试中：
	 * - CLIENT: max_send_wr 决定了并发的 WRITE 请求数（tx_depth）
	 * - SERVER: 虽然配置了这些参数，但实际不使用 Send Queue
	 */
	attr.cap.max_inline_data = user_param->inline_size;
	if (!(user_param->connection_type == DC &&
			is_dc_server_side)) {
		attr.cap.max_send_wr  = user_param->tx_depth;
		attr.cap.max_send_sge = MAX_SEND_SGE;
	}
	fprintf(stderr, "[DEBUG] ctx_qp_create: Send queue - max_send_wr=%d, max_send_sge=%d, max_inline_data=%d\n",
		attr.cap.max_send_wr, attr.cap.max_send_sge, attr.cap.max_inline_data);

	/* 配置接收队列参数（Receive Queue）
	 * - max_recv_wr: 接收队列深度（Receive Queue Depth）
	 *   * 来源：-r 参数，默认 512（write_bw）
	 * - max_recv_sge: 接收 Scatter-Gather Entry 数量
	 *   * 默认 MAX_RECV_SGE (通常为 1)
	 * - SRQ (Shared Receive Queue): 多个 QP 共享一个接收队列
	 *
	 * 在 RDMA WRITE 测试中：
	 * - CLIENT: 不需要接收队列（单边操作，不接收数据）
	 * - SERVER: 同样不需要接收队列（数据直接 DMA 到指定内存）
	 * - 但为了兼容性和初始化流程，仍会配置这些参数
	 */
	if (user_param->use_srq &&
			(user_param->tst == LAT ||
			 user_param->machine == SERVER ||
			 user_param->duplex == ON)) {
		attr.srq = ctx->srq;
		if (user_param->connection_type != DC) {
			attr.cap.max_recv_wr  = 0;
			attr.cap.max_recv_sge = 0;
		}
		fprintf(stderr, "[DEBUG] ctx_qp_create: Using SRQ (Shared Receive Queue)\n");
	} else {
		attr.srq = NULL;
		if (user_param->connection_type != DC) {
			attr.cap.max_recv_wr  = user_param->rx_depth;
			attr.cap.max_recv_sge = MAX_RECV_SGE;
		}
		fprintf(stderr, "[DEBUG] ctx_qp_create: Receive queue - max_recv_wr=%d, max_recv_sge=%d\n",
			attr.cap.max_recv_wr, attr.cap.max_recv_sge);
	}

	/* 设置 QP 类型（QP Type）
	 * - RC (Reliable Connection): 可靠连接，支持所有 RDMA 操作
	 *   * write_bw 默认使用 RC
	 *   * 提供可靠传输保证（ACK/NACK 机制）
	 *   * 支持 SEND, WRITE, READ, ATOMIC 操作
	 * - UC (Unreliable Connection): 不可靠连接
	 *   * 不支持 RDMA READ 和 ATOMIC
	 * - UD (Unreliable Datagram): 无连接数据报
	 *   * 只支持 SEND 操作
	 * - DC (Dynamically Connected): 动态连接（Mellanox 特性）
	 * - RawEth: 原始以太网包
	 * - SRD: Scalable Reliable Datagram（AWS EFA 特性）
	 *
	 * 来源：-c 参数，默认 RC
	 */
	switch (user_param->connection_type) {

		case RC : attr.qp_type = IBV_QPT_RC; break;
		case UC : attr.qp_type = IBV_QPT_UC; break;
		case UD : attr.qp_type = IBV_QPT_UD; break;
		#ifdef HAVE_IBV_WR_API
		case DC : attr.qp_type = IBV_QPT_DRIVER; break;
		#endif
		#ifdef HAVE_RAW_ETH
		case RawEth : attr.qp_type = IBV_QPT_RAW_PACKET; break;
		#endif
		#ifdef HAVE_SRD
		case SRD: attr.qp_type = IBV_QPT_DRIVER; break;
		#endif
		default:  fprintf(stderr, "Unknown connection type \n");
			  return NULL;
	}
	fprintf(stderr, "[DEBUG] ctx_qp_create: QP type set to %d (RC=2, UC=3, UD=4)\n", attr.qp_type);

	/* 设置操作标志（Send Operation Flags）
	 * 这些标志告诉硬件该 QP 支持哪些 RDMA 操作类型
	 * 只有新版 WR API (IBV_WR_API) 才需要显式设置
	 *
	 * 在 write_bw 中（user_param->verb == WRITE）：
	 * - opcode = IBV_WR_RDMA_WRITE
	 * - 设置 IBV_QP_EX_WITH_RDMA_WRITE 标志
	 * - 这允许 QP 执行 RDMA WRITE 操作
	 *
	 * RDMA WRITE 的特点：
	 * - 单边操作（One-sided）
	 * - CLIENT 在 WQE 中指定 SERVER 的远程地址和 rkey
	 * - SERVER 端不需要 post receive，数据直接 DMA 到指定内存
	 */
	#ifdef HAVE_IBV_WR_API
	if (user_param->verb == ATOMIC) {
		opcode = opcode_atomic_array[user_param->atomicType];
		if(0);
		else if (opcode == IBV_WR_ATOMIC_FETCH_AND_ADD)
			attr_ex.send_ops_flags |= IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD;
		else if (opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
			attr_ex.send_ops_flags |= IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP;
	}
	else {
		opcode = opcode_verbs_array[user_param->verb];
		if(0);
		else if (opcode == IBV_WR_SEND)
			attr_ex.send_ops_flags |= IBV_QP_EX_WITH_SEND;
		else if (opcode == IBV_WR_RDMA_WRITE) {
			attr_ex.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE;
			fprintf(stderr, "[DEBUG] ctx_qp_create: Set IBV_QP_EX_WITH_RDMA_WRITE flag for WRITE operation\n");
		}
		else if (opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			attr_ex.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM;
		else if (opcode == IBV_WR_RDMA_READ)
			attr_ex.send_ops_flags |= IBV_QP_EX_WITH_RDMA_READ;
	}

	attr_ex.pd = ctx->pad;

	attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS | IBV_QP_INIT_ATTR_PD;
	attr_ex.send_cq = attr.send_cq;
	attr_ex.recv_cq = attr.recv_cq;
	attr_ex.cap.max_send_wr = attr.cap.max_send_wr;
	attr_ex.cap.max_send_sge = attr.cap.max_send_sge;
	attr_ex.qp_type = attr.qp_type;
	attr_ex.srq = attr.srq;
	attr_ex.cap.max_inline_data = attr.cap.max_inline_data;
	attr_ex.cap.max_recv_wr  = attr.cap.max_recv_wr;
	attr_ex.cap.max_recv_sge = attr.cap.max_recv_sge;
	#endif

	/* RDMA CM 路径：使用 -R 参数时通过 RDMA CM 创建 QP
	 *
	 * RDMA CM (Connection Manager) 是更高层的连接管理接口，类似于 socket API
	 * 提供以下便利：
	 * - 自动地址解析和路由查找
	 * - 自动 QP 状态转换（INIT → RTR → RTS）
	 * - 统一的连接建立流程（CLIENT/SERVER）
	 *
	 * QP 创建方式：
	 * 1. 新版 API: rdma_create_qp_ex() - 支持扩展属性（attr_ex）
	 *    - 需要显式设置 send_ops_flags（如 IBV_QP_EX_WITH_RDMA_WRITE）
	 *    - 支持新的 WR API（ibv_wr_start/ibv_wr_complete）
	 * 2. 旧版 API: rdma_create_qp() - 使用标准属性（attr）
	 *    - 兼容旧的 ibv_post_send API
	 *
	 * QP 与 rdma_cm_id 的关系：
	 * - QP 会自动绑定到 ctx->cm_id（rdma_cm_id 结构）
	 * - QP 通过 ctx->cm_id->qp 访问
	 * - RDMA CM 事件会自动更新 QP 状态
	 *
	 * 在 RDMA WRITE 测试中：
	 * - CLIENT: 使用这个 QP 执行 ibv_post_send(IBV_WR_RDMA_WRITE)
	 * - SERVER: QP 被创建但主要用于接收连接，测试期间不主动使用
	 *
	 * 与传统 ibv_create_qp() 的区别：
	 * - 传统方式需要手动 modify_qp 转换状态，手动交换 QPN/LID/GID
	 * - RDMA CM 方式自动处理所有这些细节
	 */
	if (user_param->work_rdma_cm) {
		fprintf(stderr, "[DEBUG] ctx_qp_create [%s]: Using RDMA CM to create QP (bound to rdma_cm_id)\n",
			user_param->machine == SERVER ? "SERVER" : "CLIENT");
		#ifdef HAVE_IBV_WR_API
		if (!user_param->use_old_post_send)
		{
			fprintf(stderr, "[DEBUG] ctx_qp_create: Creating QP with new API (rdma_create_qp_ex)\n");
			if (rdma_create_qp_ex(ctx->cm_id, &attr_ex))
			{
				fprintf(stderr, "Couldn't create rdma new QP - %s\n", strerror(errno));
			}
			else
			{
				qp = ctx->cm_id->qp;
				fprintf(stderr, "[DEBUG] ctx_qp_create: RDMA CM QP created successfully via rdma_create_qp_ex\n");
				fprintf(stderr, "[DEBUG]   - QP bound to rdma_cm_id: %p\n", ctx->cm_id);
				fprintf(stderr, "[DEBUG]   - QP number (qp_num): %u\n", qp->qp_num);
				fprintf(stderr, "[DEBUG]   - QP will be auto-managed by RDMA CM (state transitions handled automatically)\n");
			}
		}
		else
		#endif
			fprintf(stderr, "[DEBUG] ctx_qp_create: Creating QP with old API (rdma_create_qp)\n");
			if (rdma_create_qp(ctx->cm_id, ctx->pd, &attr))
			{
				fprintf(stderr, "Couldn't create rdma old QP - %s\n", strerror(errno));
			}
			else
			{
				qp = ctx->cm_id->qp;
				fprintf(stderr, "[DEBUG] ctx_qp_create: RDMA CM QP created successfully via rdma_create_qp\n");
				fprintf(stderr, "[DEBUG]   - QP bound to rdma_cm_id: %p\n", ctx->cm_id);
				fprintf(stderr, "[DEBUG]   - QP number (qp_num): %u\n", qp->qp_num);
				fprintf(stderr, "[DEBUG]   - QP will be auto-managed by RDMA CM (state transitions handled automatically)\n");
			}

	} else if (user_param->connection_type == SRD) {
		#ifdef HAVE_SRD
		#ifdef HAVE_IBV_WR_API
		efa_attr.driver_qp_type = EFADV_QP_DRIVER_TYPE_SRD;
		#ifdef HAVE_SRD_WITH_UNSOLICITED_WRITE_RECV
		if (user_param->use_unsolicited_write)
			efa_attr.flags |= EFADV_QP_FLAGS_UNSOLICITED_WRITE_RECV;
		#endif
		qp = efadv_create_qp_ex(ctx->context, &attr_ex,
					&efa_attr, sizeof(efa_attr));
		#else
		qp = efadv_create_driver_qp(ctx->pd, &attr,
					    EFADV_QP_DRIVER_TYPE_SRD);
		#endif
		#endif
	} else {
		#ifdef HAVE_IBV_WR_API
		if (!user_param->use_old_post_send)
		{
			#ifdef HAVE_MLX5DV
			#ifdef HAVE_OOO_RECV_WRS
			// OOO_RECV_WRS is not supported by non-mlnx devices
			is_mlnx_device = get_device_vendor(ctx->context) == MLNX_VENDOR_ID;

			if (!user_param->no_enhanced_reorder && is_mlnx_device && user_param->connection_type != UD && user_param->connection_type != UC){
				ctx_dv.comp_mask = MLX5DV_CONTEXT_MASK_OOO_RECV_WRS;

				int ret = mlx5dv_query_device(ctx->context, &ctx_dv);

				if (ret) {
					fprintf(stderr, "Failed to query device capabilities, ret=%d\n", ret);
					return NULL;
				}

				if (ctx_dv.comp_mask & MLX5DV_CONTEXT_MASK_OOO_RECV_WRS) {
					if ((user_param->connection_type == RC && ctx_dv.ooo_recv_wrs_caps.max_rc < user_param->rx_depth) ||
					(user_param->connection_type == DC && ctx_dv.ooo_recv_wrs_caps.max_dct < user_param->rx_depth))
					{
						fprintf(stderr, "RX Depth=%d  must not exceed the maximal OOO receive WR's\n", user_param->rx_depth);
						return NULL;
						}
					user_param->use_enhanced_reorder = ON;
					attr_dv.create_flags |= MLX5DV_QP_CREATE_OOO_DP;
					attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
				}
			}
			#endif
			if (user_param->connection_type == DC)
			{
				attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;

				if (is_dc_server_side)
				{
					attr_ex.srq = ctx->srq;
					attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCT;
					attr_dv.dc_init_attr.dct_access_key = DC_KEY;
					attr_ex.comp_mask &= ~IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
				}
				else
				{
					attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCI;
					attr_dv.create_flags |= MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE;
					attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
					attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
					#ifdef HAVE_DCS
					if (user_param->log_dci_streams) {
						attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS;
						attr_dv.dc_init_attr.dci_streams.log_num_concurent = user_param->log_dci_streams;
					}
					#endif
				}
				qp = mlx5dv_create_qp(ctx->context, &attr_ex, &attr_dv);
			}
			#ifdef HAVE_AES_XTS
			else if (user_param->aes_xts) {
				attr_ex.cap.max_send_wr = user_param->tx_depth * 2;
				attr_ex.cap.max_inline_data = AES_XTS_INLINE;
				attr_dv.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS;
				attr_dv.send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE;
				attr_dv.create_flags |= MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE;
				qp = mlx5dv_create_qp(ctx->context, &attr_ex, &attr_dv);
			}
			#endif // HAVE_AES_XTS
			#ifdef HAVE_SIG_OFFLOAD
			else if (user_param->sig_offload) {
				/* 1 RDMA + 1 UMR + 1 SET_PSV */
				attr_ex.cap.max_send_wr = user_param->tx_depth * 3;
				attr_ex.cap.max_inline_data = 512;
				attr_dv.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS;
				attr_dv.send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE;
				attr_dv.create_flags |= MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE;
				qp = mlx5dv_create_qp(ctx->context, &attr_ex, &attr_dv);
			}
			#endif // HAVE_AES_XTS
			#ifdef HAVE_OOO_RECV_WRS
			else if (ctx_dv.comp_mask & MLX5DV_CONTEXT_MASK_OOO_RECV_WRS) {
				qp = mlx5dv_create_qp(ctx->context, &attr_ex, &attr_dv);
			}
			#endif
			else
			#endif // HAVE_MLX5DV
			#ifdef HAVE_HNSDV
			if (user_param->congest_type) {
				hns_attr.comp_mask = HNSDV_QP_INIT_ATTR_MASK_QP_CONGEST_TYPE;
				hns_attr.congest_type = user_param->congest_type;
				qp = hnsdv_create_qp(ctx->context, &attr_ex, &hns_attr);
			}
			else
			#endif //HAVE_HNSDV
				qp = ibv_create_qp_ex(ctx->context, &attr_ex);
		}
		else
		#endif // HAVE_IBV_WR_API
			qp = ibv_create_qp(ctx->pd, &attr);
	}

	if (qp == NULL && errno == ENOMEM) {
		fprintf(stderr, "Requested QP size might be too big. Try reducing TX depth and/or inline size.\n");
		fprintf(stderr, "Current TX depth is %d and inline size is %d .\n", user_param->tx_depth, user_param->inline_size);
	}

	#ifdef HAVE_IBV_WR_API
	if (!user_param->use_old_post_send)
		qp_cap = &attr_ex.cap;
	#endif

	if (user_param->inline_size > qp_cap->max_inline_data) {
		printf("  Actual inline-size(%d) < requested inline-size(%d)\n",
			qp_cap->max_inline_data, user_param->inline_size);
		user_param->inline_size = qp_cap->max_inline_data;
	}

	/* 最终 QP 创建结果汇总 */
	if (qp != NULL) {
		fprintf(stderr, "[DEBUG] ctx_qp_create [%s]: QP #%d created successfully\n",
			user_param->machine == SERVER ? "SERVER" : "CLIENT", qp_index);
		fprintf(stderr, "[DEBUG]   - QP number: %u\n", qp->qp_num);
		fprintf(stderr, "[DEBUG]   - QP type: %d (RC=2, UC=3, UD=4)\n", attr.qp_type);
		fprintf(stderr, "[DEBUG]   - Send queue: max_wr=%d, max_sge=%d, max_inline=%d\n",
			qp_cap->max_send_wr, qp_cap->max_send_sge, qp_cap->max_inline_data);
		fprintf(stderr, "[DEBUG]   - Recv queue: max_wr=%d, max_sge=%d\n",
			qp_cap->max_recv_wr, qp_cap->max_recv_sge);
		fprintf(stderr, "[DEBUG]   - RDMA CM managed: %s\n",
			user_param->work_rdma_cm ? "YES (auto state transitions)" : "NO (manual modify_qp needed)");
		if (user_param->verb == WRITE) {
			fprintf(stderr, "[DEBUG]   - Operation: RDMA WRITE (single-sided, CLIENT post WRITE, SERVER passive)\n");
		}
	} else {
		fprintf(stderr, "[ERROR] ctx_qp_create [%s]: Failed to create QP #%d\n",
			user_param->machine == SERVER ? "SERVER" : "CLIENT", qp_index);
	}

	return qp;
}

/******************************************************************************
 *
 ******************************************************************************/
int ctx_modify_qp_to_init(struct ibv_qp *qp,struct perftest_parameters *user_param, int qp_index)
{
	int num_of_qps = user_param->num_of_qps;
	int num_of_qps_per_port = user_param->num_of_qps / 2;

	struct ibv_qp_attr attr;
	int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT;
	int is_dc_server_side = 0;

	int ret = 0;

	memset(&attr, 0, sizeof(struct ibv_qp_attr));
	attr.qp_state        = IBV_QPS_INIT;
	attr.pkey_index      = user_param->pkey_index;

	if ((user_param->connection_type == DC || user_param->use_xrc) && (user_param->duplex || user_param->tst == LAT)) {
		num_of_qps /= 2;
		num_of_qps_per_port = num_of_qps / 2;
	}

	is_dc_server_side = ((!(user_param->duplex || user_param->tst == LAT) &&
						 (user_param->machine == SERVER)) ||
						 ((user_param->duplex || user_param->tst == LAT) &&
						 (qp_index >= num_of_qps)));

	if (user_param->dualport==ON) {
		static int portindex=0;  /* for dual-port support */
		if (portindex % num_of_qps < num_of_qps_per_port) {
			attr.port_num = user_param->ib_port;
			user_param->port_by_qp[portindex] = 0;
		} else {
			attr.port_num = user_param->ib_port2;
			user_param->port_by_qp[portindex] = 1;
		}
		portindex++;

	} else {
		attr.port_num = user_param->ib_port;
	}

	if (user_param->connection_type == RawEth) {
		flags = IBV_QP_STATE | IBV_QP_PORT;

	} else if (user_param->connection_type == UD || user_param->connection_type == SRD) {
		attr.qkey = DEFF_QKEY;
		flags |= IBV_QP_QKEY;
	} else if (!(user_param->connection_type == DC &&
			!is_dc_server_side)) {
		switch (user_param->verb) {
			case ATOMIC: attr.qp_access_flags = IBV_ACCESS_REMOTE_ATOMIC; break;
			case READ  : attr.qp_access_flags = IBV_ACCESS_REMOTE_READ;  break;
			case WRITE_IMM:
			case WRITE :
				     attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE; break;
			case SEND  : attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;
		}
		flags |= IBV_QP_ACCESS_FLAGS;
	}
	ret = ibv_modify_qp(qp, &attr, flags);

	if (ret) {
		fprintf(stderr, "Failed to modify QP to INIT, ret=%d\n",ret);
		return 1;
	}
	return 0;
}

/******************************************************************************
 *
 ******************************************************************************/
static int ctx_modify_qp_to_rtr(struct ibv_qp *qp,
		struct ibv_qp_attr *attr,
		struct perftest_parameters *user_param,
		struct pingpong_dest *dest,
		struct pingpong_dest *my_dest,
		int qp_index)
{
	int num_of_qps = user_param->num_of_qps;
	int num_of_qps_per_port = user_param->num_of_qps / 2;
	int is_dc_server_side = 0;
	int flags = IBV_QP_STATE;
	int ooo_flags = 0;

	attr->qp_state = IBV_QPS_RTR;
	attr->ah_attr.src_path_bits = 0;

	/* in xrc with bidirectional,
	 * there are send qps and recv qps. the actual number of send/recv qps
	 * is num_of_qps / 2.
	 */
	if ((user_param->connection_type == DC || user_param->use_xrc) && (user_param->duplex || user_param->tst == LAT)) {
		num_of_qps /= 2;
		num_of_qps_per_port = num_of_qps / 2;
	}
	is_dc_server_side = ((!(user_param->duplex || user_param->tst == LAT) &&
						 (user_param->machine == SERVER)) ||
						  ((user_param->duplex || user_param->tst == LAT) &&
						 (qp_index >= num_of_qps)));
	/* first half of qps are for ib_port and second half are for ib_port2
	 * in xrc with bidirectional, the first half of qps are xrc_send qps and
	 * the second half are xrc_recv qps. the first half of the send/recv qps
	 * are for ib_port1 and the second half are for ib_port2
	 */
	if (user_param->dualport == ON && (qp_index % num_of_qps >= num_of_qps_per_port))
		attr->ah_attr.port_num = user_param->ib_port2;
	else
		attr->ah_attr.port_num = user_param->ib_port;

	if (user_param->connection_type != RawEth) {
		attr->ah_attr.dlid = (user_param->dlid) ? user_param->dlid : dest->lid;
		attr->ah_attr.sl = user_param->sl;

		if (((attr->ah_attr.port_num == user_param->ib_port) && (user_param->gid_index == DEF_GID_INDEX))
				|| ((attr->ah_attr.port_num == user_param->ib_port2) && (user_param->gid_index2 == DEF_GID_INDEX) && user_param->dualport)) {

			attr->ah_attr.is_global = 0;
		} else {

			attr->ah_attr.is_global  = 1;
			attr->ah_attr.grh.dgid = dest->gid;
			attr->ah_attr.grh.sgid_index = (attr->ah_attr.port_num == user_param->ib_port) ? user_param->gid_index : user_param->gid_index2;
			attr->ah_attr.grh.hop_limit = 0xFF;
			attr->ah_attr.grh.traffic_class = user_param->traffic_class;
			if (user_param->flow_label) {
				attr->ah_attr.grh.flow_label = user_param->flow_label[user_param->flow_label[1] % user_param->flow_label[0] + 2];
				user_param->flow_label[1] = user_param->flow_label[1] + 1;
			}
		}
		if (user_param->connection_type != UD && user_param->connection_type != SRD) {
			if (user_param->connection_type == DC) {
				attr->path_mtu = user_param->curr_mtu;
				flags |= IBV_QP_AV | IBV_QP_PATH_MTU;
				if (is_dc_server_side)
				{
					attr->min_rnr_timer = MIN_RNR_TIMER;
					flags |= IBV_QP_MIN_RNR_TIMER;
				} //DCT
			}
			else {
				attr->path_mtu = user_param->curr_mtu;
				attr->dest_qp_num = dest->qpn;
				attr->rq_psn = dest->psn;

				flags |= (IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN);

				if (user_param->connection_type == RC || user_param->connection_type == XRC) {

					attr->max_dest_rd_atomic = my_dest->out_reads;
					attr->min_rnr_timer = MIN_RNR_TIMER;
					flags |= (IBV_QP_MIN_RNR_TIMER | IBV_QP_MAX_DEST_RD_ATOMIC);
				}
			}
		}
	}
	else if (user_param->raw_qos) {
		attr->ah_attr.sl = user_param->sl;
		flags |= IBV_QP_AV;
	}

	#ifdef HAVE_OOO_ATTR
		ooo_flags |= IBV_QP_OOO_RW_DATA_PLACEMENT;
	#endif

	if (user_param->use_ooo)
		flags |= ooo_flags;
	return ibv_modify_qp(qp, attr, flags);
}

/******************************************************************************
 *
 ******************************************************************************/
static int ctx_modify_qp_to_rts(struct ibv_qp *qp,
		struct ibv_qp_attr *attr,
		struct perftest_parameters *user_param,
		struct pingpong_dest *dest,
		struct pingpong_dest *my_dest)
{
	int flags = IBV_QP_STATE;

	attr->qp_state = IBV_QPS_RTS;

	if (user_param->connection_type != RawEth) {

		flags |= IBV_QP_SQ_PSN;
		attr->sq_psn = my_dest->psn;

		if (user_param->connection_type == DC ||
			user_param->connection_type == RC ||
			user_param->connection_type == XRC) {

			attr->timeout   = user_param->qp_timeout;
			attr->retry_cnt = 7;
			attr->rnr_retry = 7;
			attr->max_rd_atomic  = dest->out_reads;
			flags |= (IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC);
		}
	}

	#ifdef HAVE_PACKET_PACING
	if (user_param->rate_limit_type == PP_RATE_LIMIT) {
		attr->rate_limit = user_param->rate_limit;
		flags |= IBV_QP_RATE_LIMIT;
	}
	#endif

	return ibv_modify_qp(qp, attr, flags);
}

/******************************************************************************
 *
 ******************************************************************************/
int ctx_connect(struct pingpong_context *ctx,
		struct pingpong_dest *dest,
		struct perftest_parameters *user_param,
		struct pingpong_dest *my_dest)
{
	int i;
	struct ibv_qp_attr attr;
	int xrc_offset = 0;

	if((user_param->use_xrc || user_param->connection_type == DC) && (user_param->duplex || user_param->tst == LAT)) {
		xrc_offset = user_param->num_of_qps / 2;
	}
	for (i=0; i < user_param->num_of_qps; i++) {


		memset(&attr, 0, sizeof attr);

		if (user_param->rate_limit_type == HW_RATE_LIMIT)
			attr.ah_attr.static_rate = user_param->valid_hw_rate_limit_index;

		#if defined (HAVE_PACKET_PACING)
		if (user_param->rate_limit_type == PP_RATE_LIMIT) {
			if (check_packet_pacing_support(ctx) == FAILURE) {
				fprintf(stderr, "Packet Pacing isn't supported.\n");
				return FAILURE;
			}
		}
		#endif

		if ((i >= xrc_offset) && (user_param->use_xrc || user_param->connection_type == DC) && (user_param->duplex || user_param->tst == LAT))
			xrc_offset = -1*xrc_offset;


		if(ctx_modify_qp_to_rtr(ctx->qp[i], &attr, user_param, &dest[xrc_offset + i], &my_dest[i], i)) {
			fprintf(stderr, "Failed to modify QP %d to RTR\n",ctx->qp[i]->qp_num);
			return FAILURE;
		}
		if (user_param->connection_type == DC) {
			if ( ((!(user_param->duplex || user_param->tst == LAT) && (user_param->machine == SERVER) )
				|| ((user_param->duplex || user_param->tst == LAT) && (i >= user_param->num_of_qps/2)))) {
				continue;
			}
		}
		if (user_param->tst == LAT || user_param->machine == CLIENT || user_param->duplex) {
			if(ctx_modify_qp_to_rts(ctx->qp[i], &attr, user_param, &dest[xrc_offset + i], &my_dest[i])) {
				fprintf(stderr, "Failed to modify QP to RTS\n");
				return FAILURE;
			}
		}

		if (((user_param->connection_type == UD || user_param->connection_type == DC || user_param->connection_type == SRD) &&
				(user_param->tst == LAT || user_param->machine == CLIENT || user_param->duplex)) ||
				(user_param->connection_type == SRD && (user_param->verb == READ || user_param->verb == WRITE ||
									user_param->verb == WRITE_IMM))) {

			ctx->ah[i] = ibv_create_ah(ctx->pd,&(attr.ah_attr));

			if (!ctx->ah[i]) {
				fprintf(stderr, "Failed to create AH\n");
				return FAILURE;
			}
			user_param->ah_allocated = 1;
		}

		if (user_param->rate_limit_type == HW_RATE_LIMIT) {
			struct ibv_qp_attr qp_attr;
			struct ibv_qp_init_attr init_attr;
			int err, qp_static_rate = 0;

			memset(&qp_attr,0,sizeof(struct ibv_qp_attr));
			memset(&init_attr,0,sizeof(struct ibv_qp_init_attr));

			err = ibv_query_qp(ctx->qp[i], &qp_attr, IBV_QP_AV, &init_attr);
			if (err)
				fprintf(stderr, "ibv_query_qp failed to get ah_attr\n");
			else
				qp_static_rate = (int)(qp_attr.ah_attr.static_rate);

			//- Fall back to SW Limit only if flag undefined
			if(err ||
			   qp_static_rate != user_param->valid_hw_rate_limit_index ||
			   user_param->link_type != IBV_LINK_LAYER_INFINIBAND) {
				if(!user_param->is_rate_limit_type) {
					user_param->rate_limit_type = SW_RATE_LIMIT;
					fprintf(stderr, "\x1b[31mThe QP failed to accept HW rate limit, providing SW rate limit \x1b[0m\n");
				} else {
					fprintf(stderr, "\x1b[31mThe QP failed to accept HW rate limit  \x1b[0m\n");
					return FAILURE;
				}
			}
		}

		if((user_param->use_xrc || user_param->connection_type == DC) && (user_param->duplex || user_param->tst == LAT))
			xrc_offset = user_param->num_of_qps / 2;

	}
	return SUCCESS;
}

/******************************************************************************
 *
 ******************************************************************************/
void ctx_set_send_wqes(struct pingpong_context *ctx,
		struct perftest_parameters *user_param,
		struct pingpong_dest *rem_dest)
{
	ctx_set_send_reg_wqes(ctx,user_param,rem_dest);
}

/* ctx_post_send_work_request_func_pointer.
 *
 * Description :
 *
 * Chooses the correct pointer to be used to call funtion for posting WR
 * using new posting API.
 *
 * Parameters :
 *
 *	ctx         - Test Context.
 *	user_param  - user_parameters struct for this test.
 *
 * Return Value : void.
 *
 */
#ifdef HAVE_IBV_WR_API
static void ctx_post_send_work_request_func_pointer(struct pingpong_context *ctx,
		struct perftest_parameters *user_param)
{
	int use_inl = user_param->size <= user_param->inline_size;
	int use_enc = user_param->aes_xts;
	switch (user_param->connection_type) {
	case DC:
		switch (user_param->verb) {
			case SEND:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_inl_dc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_sge_dc;
				}
				break;
			case WRITE_IMM:
			case WRITE:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_inl_dc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_sge_dc;
				}
				break;
			case READ:
				ctx->new_post_send_work_request_func_pointer = &new_post_read_sge_dc;
				break;
			case ATOMIC:
				if (user_param->atomicType == FETCH_AND_ADD) {
					ctx->new_post_send_work_request_func_pointer = &new_post_atomic_fa_sge_dc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_atomic_cs_sge_dc;
				}
				break;
			default:
				fprintf(stderr, "The post send properties are not supported on DC. \n");
		}
		break;
	case RC:
		switch (user_param->verb) {
			case SEND:
				if (use_enc) {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_sge_enc_rc;
				}
				else if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_inl_rc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_sge_rc;
				}
				break;
			case WRITE_IMM:
			case WRITE:
				if(use_enc) {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_sge_enc_rc;
				}
				else if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_inl_rc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_sge_rc;
				}
				break;
			case READ:
				if(use_enc) {
					ctx->new_post_send_work_request_func_pointer = &new_post_read_sge_enc_rc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_read_sge_rc;
				}
				break;
			case ATOMIC:
				if (user_param->atomicType == FETCH_AND_ADD) {
					ctx->new_post_send_work_request_func_pointer = &new_post_atomic_fa_sge_rc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_atomic_cs_sge_rc;
				}
				break;
			default:
				fprintf(stderr, "The post send properties are not supported on RC. \n");
		}
		break;
	case UD:
		switch (user_param->verb) {
			case SEND:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_inl_ud;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_sge_ud;
				}
				break;
			default:
				fprintf(stderr, "The post send properties are not supported on UD. \n");
		}
		break;
	case UC:
		switch (user_param->verb) {
			case SEND:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_inl_uc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_sge_uc;
				}
				break;
			case WRITE_IMM:
			case WRITE:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_inl_uc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_sge_uc;
				}
				break;
			default:
				fprintf(stderr, "The post send properties are not supported on UD. \n");
		}
		break;
	case XRC:
		switch (user_param->verb) {
			case SEND:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_inl_xrc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_sge_xrc;
				}
				break;
			case WRITE_IMM:
			case WRITE:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_inl_xrc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_sge_xrc;
				}
				break;
			case READ:
				ctx->new_post_send_work_request_func_pointer = &new_post_read_sge_xrc;
				break;
			case ATOMIC:
				if (user_param->atomicType == FETCH_AND_ADD) {
					ctx->new_post_send_work_request_func_pointer = &new_post_atomic_fa_sge_xrc;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_atomic_cs_sge_xrc;
				}
				break;
			default:
				fprintf(stderr, "The post send properties are not supported on RC. \n");
		}
		break;
	case SRD:
		switch (user_param->verb) {
			case SEND:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_inl_srd;
				}
				else {
					ctx->new_post_send_work_request_func_pointer = &new_post_send_sge_srd;
				}
				break;
			case READ:
				ctx->new_post_send_work_request_func_pointer = &new_post_read_sge_srd;
				break;
			case WRITE_IMM:
			case WRITE:
				if (use_inl) {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_inl_srd;
				} else {
					ctx->new_post_send_work_request_func_pointer = &new_post_write_sge_srd;
				}
				break;
			default:
				fprintf(stderr, "The post send properties are not supported on SRD.\n");
		}
		break;
	default:
		fprintf(stderr, "Unsupported transport. \n");
	}
}
#endif

/******************************************************************************
 * ctx_set_send_reg_wqes - 设置发送工作队列元素 (WQE)
 *
 * 功能说明：
 * 为所有 QP 准备发送工作请求 (Work Requests)，配置 RDMA 操作所需的参数
 *
 * 关键配置项（针对 RDMA WRITE 非 immediate 模式）：
 * - 本地内存地址 (sge_list[].addr): 从 ctx->buf[] 获取
 * - 本地内存长度 (sge_list[].length): user_param->size
 * - 本地key (sge_list[].lkey): 从 MR (ctx->mr[]) 获取
 * - 远程内存地址 (wr.rdma.remote_addr): 从 rem_dest[].vaddr 获取
 * - 远程key (wr.rdma.rkey): 从 rem_dest[].rkey 获取
 * - 操作码 (wr.opcode): IBV_WR_RDMA_WRITE (对于 WRITE verb)
 * - 完成标志 (send_flags): 根据 cq_mod 设置 IBV_SEND_SIGNALED
 ******************************************************************************/
void ctx_set_send_reg_wqes(struct pingpong_context *ctx,
		struct perftest_parameters *user_param,
		struct pingpong_dest *rem_dest)
{
	int i,j;
	int num_of_qps = user_param->num_of_qps;
	int xrc_offset = 0;
	uint32_t remote_qkey;

	fprintf(stderr, "[DEBUG] ctx_set_send_reg_wqes: Configuring WQEs for %d QPs\n", num_of_qps);
	fprintf(stderr, "[DEBUG] ctx_set_send_reg_wqes: verb=%d (WRITE=%d), size=%lu, post_list=%d\n",
		user_param->verb, WRITE, user_param->size, user_param->post_list);

	if((user_param->use_xrc || user_param->connection_type == DC) && (user_param->duplex || user_param->tst == LAT)) {
		num_of_qps /= 2;
		xrc_offset = num_of_qps;
	}

	for (i = 0; i < num_of_qps ; i++) {
		if (user_param->connection_type == DC)
		{
			ctx->r_dctn[i] = rem_dest[xrc_offset + i].qpn;
		}
		memset(&ctx->wr[i*user_param->post_list],0,sizeof(struct ibv_send_wr));
		ctx->sge_list[i*user_param->post_list].addr = (uintptr_t)ctx->buf[i];

		if (user_param->mac_fwd) {
			if (user_param->mr_per_qp) {
				ctx->sge_list[i*user_param->post_list].addr =
					(uintptr_t)ctx->buf[0] + (num_of_qps + i)*BUFF_SIZE(ctx->size,ctx->cycle_buffer);
			} else {
				ctx->sge_list[i*user_param->post_list].addr = (uintptr_t)ctx->buf[i];
			}
		}

		/* 对于 RDMA 操作（WRITE/READ），设置远程内存地址
		 * remote_addr 指向对端的内存地址，数据将被写入此地址（WRITE）或从此地址读取（READ）
		 */
		if (user_param->verb == WRITE || user_param->verb == WRITE_IMM || user_param->verb == READ) {
			ctx->wr[i*user_param->post_list].wr.rdma.remote_addr   = rem_dest[xrc_offset + i].vaddr;
			fprintf(stderr, "[DEBUG] ctx_set_send_reg_wqes: QP[%d] remote_addr=0x%lx\n",
				i, rem_dest[xrc_offset + i].vaddr);
		}
		else if (user_param->verb == ATOMIC)
			ctx->wr[i*user_param->post_list].wr.atomic.remote_addr = rem_dest[xrc_offset + i].vaddr;

		if (user_param->tst == BW || user_param->tst == LAT_BY_BW) {

			ctx->scnt[i] = 0;
			ctx->ccnt[i] = 0;
			ctx->my_addr[i] = (uintptr_t)ctx->buf[i];
			if (user_param->verb != SEND)
				ctx->rem_addr[i] = rem_dest[xrc_offset + i].vaddr;
		}

		for (j = 0; j < user_param->post_list; j++) {

			ctx->sge_list[i*user_param->post_list + j].length =
				(user_param->connection_type == RawEth) ? (user_param->size - HW_CRC_ADDITION) : user_param->size;

			ctx->sge_list[i*user_param->post_list + j].lkey = user_param->use_null_mr ? ctx->null_mr->lkey : ctx->mr[i]->lkey;

			if (j > 0) {

				ctx->sge_list[i*user_param->post_list +j].addr = ctx->sge_list[i*user_param->post_list + (j-1)].addr;

				if ((user_param->tst == BW || user_param->tst == LAT_BY_BW) && user_param->size <= (ctx->cycle_buffer / 2))
					increase_loc_addr(&ctx->sge_list[i*user_param->post_list +j],user_param->size,
							j-1,ctx->my_addr[i],0,ctx->cache_line_size,ctx->cycle_buffer);
			}

			ctx->wr[i*user_param->post_list + j].sg_list = &ctx->sge_list[i*user_param->post_list + j];
			ctx->wr[i*user_param->post_list + j].num_sge = MAX_SEND_SGE;
			ctx->wr[i*user_param->post_list + j].wr_id   = build_wr_id(i * user_param->post_list + j, i);

			if (j == (user_param->post_list - 1)) {
				ctx->wr[i*user_param->post_list + j].next = NULL;
			} else {
				ctx->wr[i*user_param->post_list + j].next = &ctx->wr[i*user_param->post_list+j+1];
			}

			if ((j + 1) % user_param->cq_mod == 0) {
				ctx->wr[i*user_param->post_list + j].send_flags = IBV_SEND_SIGNALED;
			} else {
				ctx->wr[i*user_param->post_list + j].send_flags = 0;
			}

			if (user_param->verb == ATOMIC) {
				ctx->wr[i*user_param->post_list + j].opcode = opcode_atomic_array[user_param->atomicType];
			}
			else {
				ctx->wr[i*user_param->post_list + j].opcode = opcode_verbs_array[user_param->verb];
			}
			/* 对于 RDMA WRITE/READ 操作，配置 RDMA 特定参数
			 * rkey: 远程内存区域的保护key，用于验证访问权限
			 *       必须与对端注册 MR 时生成的 key 匹配
			 */
			if (user_param->verb == WRITE || user_param->verb == WRITE_IMM || user_param->verb == READ) {

				ctx->wr[i*user_param->post_list + j].wr.rdma.rkey = rem_dest[xrc_offset + i].rkey;
				if (j == 0) {
					fprintf(stderr, "[DEBUG] ctx_set_send_reg_wqes: QP[%d] WR[%d] rkey=0x%x\n",
						i, j, rem_dest[xrc_offset + i].rkey);
				}
				if (user_param->connection_type == SRD)
					ctx->rem_qpn[xrc_offset + i] = rem_dest[xrc_offset + i].qpn;
				if (j > 0) {

					ctx->wr[i*user_param->post_list + j].wr.rdma.remote_addr =
						ctx->wr[i*user_param->post_list + (j-1)].wr.rdma.remote_addr;

					if ((user_param->tst == BW || user_param->tst == LAT_BY_BW ) && user_param->size <= (ctx->cycle_buffer / 2))
						increase_rem_addr(&ctx->wr[i*user_param->post_list + j],user_param->size,
								j-1,ctx->rem_addr[i],WRITE,ctx->cache_line_size,ctx->cycle_buffer);
				}

			} else if (user_param->verb == ATOMIC) {

				ctx->wr[i*user_param->post_list + j].wr.atomic.rkey = rem_dest[xrc_offset + i].rkey;

				if (j > 0) {

					ctx->wr[i*user_param->post_list + j].wr.atomic.remote_addr =
						ctx->wr[i*user_param->post_list + j-1].wr.atomic.remote_addr;
					if (user_param->tst == BW || user_param->tst == LAT_BY_BW)
						increase_rem_addr(&ctx->wr[i*user_param->post_list + j],user_param->size,
								j-1,ctx->rem_addr[i],ATOMIC,ctx->cache_line_size,ctx->cycle_buffer);
				}

				if (user_param->atomicType == FETCH_AND_ADD)
					ctx->wr[i*user_param->post_list + j].wr.atomic.compare_add = ATOMIC_ADD_VALUE;

				else
					ctx->wr[i*user_param->post_list + j].wr.atomic.swap = ATOMIC_SWAP_VALUE;


			} else if (user_param->verb == SEND) {

				if (user_param->connection_type == UD || user_param->connection_type == SRD) {

					ctx->wr[i*user_param->post_list + j].wr.ud.ah = ctx->ah[i];
					if (user_param->work_rdma_cm) {
						ctx->rem_qpn[xrc_offset + i] = ctx->cma_master.nodes[i].remote_qpn;
						remote_qkey = ctx->cma_master.nodes[i].remote_qkey;
					} else {
						ctx->rem_qpn[xrc_offset + i] = rem_dest[xrc_offset + i].qpn;
						remote_qkey = DEF_QKEY;
					}
					ctx->wr[i*user_param->post_list + j].wr.ud.remote_qkey = remote_qkey;
					ctx->wr[i*user_param->post_list + j].wr.ud.remote_qpn = ctx->rem_qpn[xrc_offset + i];
				}
			}

			if ((user_param->verb == SEND || user_param->verb == WRITE || user_param->verb == WRITE_IMM) && user_param->size <= user_param->inline_size)
				ctx->wr[i*user_param->post_list + j].send_flags |= IBV_SEND_INLINE;

			#ifdef HAVE_XRCD
			if (user_param->use_xrc)
				ctx->wr[i*user_param->post_list + j].qp_type.xrc.remote_srqn = rem_dest[xrc_offset + i].srqn;
			#endif
		}
	}
}

static uint64_t set_recv_length(struct pingpong_context *ctx,
				struct perftest_parameters *user_param)
{
	enum ctx_device current_dev = ib_dev_name(ctx->context);
	int mtu = MTU_SIZE(user_param->curr_mtu);
	uint64_t length = SIZE(user_param->connection_type, user_param->size, 1);

	if (current_dev != HNS && user_param->use_srq == ON)
		length = ((length + mtu - 1 )/ mtu) * mtu;

	return length;
}

/******************************************************************************
 *
 ******************************************************************************/
int ctx_set_recv_wqes(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	int			i = 0,j,k;
	int			num_of_qps = user_param->num_of_qps;
	struct ibv_recv_wr	*bad_wr_recv;
	int			size_per_qp = user_param->rx_depth / user_param->recv_post_list;
	uint64_t length = set_recv_length(ctx, user_param);

	/* Write w/imm completions have zero recieve buffer length */
	if (user_param->verb == WRITE_IMM)
		length = 0;

	if((user_param->use_xrc || user_param->connection_type == DC) &&
				(user_param->duplex || user_param->tst == LAT)) {

		i = user_param->num_of_qps / 2;
		num_of_qps /= 2;
	}

	if (user_param->use_srq)
		size_per_qp /= user_param->num_of_qps;
	ctx->rposted = size_per_qp * user_param->recv_post_list;

	for (k = 0; i < user_param->num_of_qps; i++,k++) {
		if (!user_param->mr_per_qp) {
			ctx->recv_sge_list[i * user_param->recv_post_list].addr = (uintptr_t)ctx->buf[0] +
				(num_of_qps + k) * ctx->send_qp_buff_size;
		} else {
			ctx->recv_sge_list[i * user_param->recv_post_list].addr = (uintptr_t)ctx->buf[i];
		}

		if (user_param->connection_type == UD)
			ctx->recv_sge_list[i * user_param->recv_post_list].addr += (ctx->cache_line_size - UD_ADDITION);

		ctx->rx_buffer_addr[i] = ctx->recv_sge_list[i * user_param->recv_post_list].addr;

		for (j = 0; j < user_param->recv_post_list; j++) {
			ctx->recv_sge_list[i * user_param->recv_post_list + j].length = length;
			ctx->recv_sge_list[i * user_param->recv_post_list + j].lkey   = user_param->use_null_mr ? ctx->null_mr->lkey : ctx->mr[i]->lkey;

			if (j > 0) {
				ctx->recv_sge_list[i * user_param->recv_post_list + j].addr = ctx->recv_sge_list[i * user_param->recv_post_list + j - 1].addr;

				if ((user_param->tst == BW || user_param->tst == LAT_BY_BW) && user_param->size <= (ctx->cycle_buffer / 2)) {
					increase_loc_addr(&ctx->recv_sge_list[i * user_param->recv_post_list + j],
							user_param->size,
							j-1,
							ctx->rx_buffer_addr[i],
							user_param->connection_type,ctx->cache_line_size,ctx->cycle_buffer);
				}
			}

			ctx->rwr[i * user_param->recv_post_list + j].sg_list = &ctx->recv_sge_list[i * user_param->recv_post_list + j];
			ctx->rwr[i * user_param->recv_post_list + j].num_sge = MAX_RECV_SGE;
			ctx->rwr[i * user_param->recv_post_list + j].wr_id   = build_wr_id(i * user_param->recv_post_list + j, i);

			if (j == (user_param->recv_post_list - 1))
				ctx->rwr[i * user_param->recv_post_list + j].next = NULL;
			else
				ctx->rwr[i * user_param->recv_post_list + j].next = &ctx->rwr[i * user_param->recv_post_list + j + 1];
		}

		for (j = 0; j < size_per_qp ; ++j) {

			if (user_param->use_srq) {

				if (ibv_post_srq_recv(ctx->srq,&ctx->rwr[i * user_param->recv_post_list], &bad_wr_recv)) {
					fprintf(stderr, "Couldn't post recv SRQ = %d: counter=%d\n",i,j);
					return 1;
				}

			} else {

				if (ibv_post_recv(ctx->qp[i],&ctx->rwr[i * user_param->recv_post_list],&bad_wr_recv)) {
					fprintf(stderr, "Couldn't post recv Qp = %d: counter=%d\n",i,j);
					return 1;
				}
			}

			if (user_param->recv_post_list == 1 && (user_param->tst == BW || user_param->tst == LAT_BY_BW) &&
					user_param->size <= (ctx->cycle_buffer / 2)) {
				increase_loc_addr(&ctx->recv_sge_list[i * user_param->recv_post_list],
						user_param->size,
						j,
						ctx->rx_buffer_addr[i],
						user_param->connection_type,ctx->cache_line_size,ctx->cycle_buffer);
			}
		}
		ctx->recv_sge_list[i * user_param->recv_post_list].addr = ctx->rx_buffer_addr[i];
	}
	return 0;
}

int ctx_alloc_credit(struct pingpong_context *ctx,
		struct perftest_parameters *user_param,
		struct pingpong_dest *my_dest)
{
	int buf_size = 2*user_param->num_of_qps*sizeof(uint32_t);
	int flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE;
	int i;

	ALLOCATE(ctx->ctrl_buf,uint32_t,2*user_param->num_of_qps);
	memset(&ctx->ctrl_buf[0],0,buf_size);

	ctx->credit_buf = (uint32_t *)ctx->ctrl_buf + user_param->num_of_qps;
	ctx->credit_cnt = user_param->rx_depth/3;

	ctx->credit_mr = ibv_reg_mr(ctx->pd,ctx->ctrl_buf,buf_size,flags);
	if (!ctx->credit_mr) {
		fprintf(stderr, "Couldn't allocate MR\n");
		return FAILURE;
	}
	for (i = 0; i < user_param->num_of_qps; i++) {
		my_dest[i].rkey  = ctx->credit_mr->rkey;
		my_dest[i].vaddr = (uintptr_t)ctx->credit_buf + i*sizeof(uint32_t);
	}
	return 0;
}

/* Should be called after the remote keys have been exchanged */
int ctx_set_credit_wqes(struct pingpong_context *ctx,
		struct perftest_parameters *user_param,
		struct pingpong_dest *rem_dest)
{
	int i;
	ALLOCATE(ctx->ctrl_wr,struct ibv_send_wr,user_param->num_of_qps);
	ALLOCATE(ctx->ctrl_sge_list,struct ibv_sge,user_param->num_of_qps);

	for (i = 0; i < user_param->num_of_qps; i++) {
		memset(&ctx->ctrl_wr[i],0,sizeof(struct ibv_send_wr));

		ctx->ctrl_sge_list[i].addr = (uintptr_t)ctx->ctrl_buf + (i*sizeof(uint32_t));
		ctx->ctrl_sge_list[i].length = sizeof(uint32_t);
		ctx->ctrl_sge_list[i].lkey = ctx->credit_mr->lkey;

		ctx->ctrl_wr[i].opcode = IBV_WR_RDMA_WRITE;
		ctx->ctrl_wr[i].sg_list = &ctx->ctrl_sge_list[i];
		ctx->ctrl_wr[i].num_sge = 1;
		ctx->ctrl_wr[i].wr_id = i;
		ctx->ctrl_wr[i].send_flags = IBV_SEND_SIGNALED;
		ctx->ctrl_wr[i].next = NULL;

		ctx->ctrl_wr[i].wr.rdma.remote_addr = rem_dest[i].vaddr;
		ctx->ctrl_wr[i].wr.rdma.rkey = rem_dest[i].rkey;
	}
	return 0;
}

static int clean_scq_credit(int send_cnt,struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	int 		i = 0, sne;
	struct ibv_wc 	*swc = NULL;
	int		return_value = 0;
	if (!send_cnt)
		return 0;

	ALLOCATE(swc,struct ibv_wc,user_param->tx_depth);
	do {
		sne = ibv_poll_cq(ctx->send_cq,user_param->tx_depth,swc);
		if (sne > 0) {
			for (i = 0; i < sne; i++) {
				if (swc[i].status != IBV_WC_SUCCESS) {
					fprintf(stderr, "Poll send CQ error status=%u qp %d\n",
							swc[i].status,(int)swc[i].qp_num);
					return_value = FAILURE;
					goto cleaning;
				}
				send_cnt--;
			}

		} else if (sne < 0) {
			fprintf(stderr, "Poll send CQ to clean credit failed ne=%d\n",sne);
			return_value = FAILURE;
			goto cleaning;
		}
	} while(send_cnt > 0);

cleaning:
	free(swc);
	return return_value;
}

/******************************************************************************
 *
 ******************************************************************************/
int perform_warm_up(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	int 			ne,qp_index,warmindex,warmupsession;
	int 			err = 0;
	struct ibv_wc 		wc;
	struct ibv_wc 		*wc_for_cleaning = NULL;
	int 			num_of_qps = user_param->num_of_qps;
	int			return_value = 0;
	int			set_signaled = 0;

	if(user_param->duplex && (user_param->use_xrc || user_param->connection_type == DC))
		num_of_qps /= 2;

	warmupsession = (user_param->post_list == 1) ? user_param->tx_depth : user_param->post_list;
	ALLOCATE(wc_for_cleaning,struct ibv_wc,user_param->tx_depth);

#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
#endif

	/* Clean up the pipe */
	ne = ibv_poll_cq(ctx->send_cq,user_param->tx_depth,wc_for_cleaning);

	for (qp_index=0 ; qp_index < num_of_qps ; qp_index++) {
		/* ask for completion on this wr */
		if (user_param->post_list == 1 && !(ctx->wr[qp_index].send_flags & IBV_SEND_SIGNALED)) {
			ctx->wr[qp_index].send_flags |= IBV_SEND_SIGNALED;
			set_signaled = 1;
		}

		for (warmindex = 0 ;warmindex < warmupsession ;warmindex += user_param->post_list) {
			err = post_send_method(ctx, qp_index, user_param);
			if (err) {
				fprintf(stderr,"Couldn't post send during warm up: qp index %d scnt=%d \n",qp_index,warmindex);
				return_value = FAILURE;
				goto cleaning;
			}
		}

		/* Clear the flag to avoid affecting subsequent tests. */
		if (set_signaled) {
			ctx->wr[qp_index].send_flags &= ~IBV_SEND_SIGNALED;
			set_signaled = 0;
		}

		do {

			ne = ibv_poll_cq(ctx->send_cq,1,&wc);
			if (ne > 0) {

				//coverity[uninit_use]
				if (wc.status != IBV_WC_SUCCESS) {
					return_value = FAILURE;
					goto cleaning;
				}

				warmindex -= user_param->post_list;

			} else if (ne < 0) {
				return_value = FAILURE;
				goto cleaning;
			}

		} while (warmindex);
	}

cleaning:
	free(wc_for_cleaning);
	return return_value;
}

/******************************************************************************
 * run_iter_bw - 执行带宽测试的主循环
 *
 * 功能说明：
 * 这是带宽测试的核心函数，负责：
 * 1. post 发送请求 (ibv_post_send)
 * 2. poll 完成队列获取完成状态 (ibv_poll_cq)
 * 3. 根据 test_type 决定运行模式：
 *    - DURATION: 运行指定时间（如 -D 60 表示 60 秒）
 *    - ITERATIONS: 运行固定迭代次数
 * 4. 收集性能数据用于计算带宽和消息速率
 *
 * 对于 RDMA WRITE（非 immediate）：
 * - 只需 post send 和 poll send CQ
 * - 不需要在接收端 post receive 或 poll recv CQ
 * - 数据直接写入远程内存，无需接收端参与
 ******************************************************************************/
int run_iter_bw(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	uint64_t           	totscnt = 0;  /* total send count - 总发送计数 */
	uint64_t       	   	totccnt = 0;  /* total completion count - 总完成计数 */
	int                	i = 0;
	int			index;
	int			ne = 0;  /* number of completions polled - poll到的完成数 */
	uint64_t	   	tot_iters;  /* total iterations for test - 总迭代次数 */
	int			err = 0;
	struct ibv_wc 	   	*wc = NULL;  /* work completion array - 工作完成数组 */
	int 			num_of_qps = user_param->num_of_qps;
	/* Rate Limiter*/
	int 			rate_limit_pps = 0;
	double 			gap_time = 0;	/* in usec */
	cycles_t 		gap_cycles = 0;	/* in cycles */
	cycles_t 		gap_deadline = 0;
	double 		number_of_bursts = 0;
	int 			burst_iter = 0;
	int 			is_sending_burst = 0;
	int 			cpu_mhz = 0;
	int 			return_value = 0;
	int			qp_index;
	int			send_flows_index = 0;
	uintptr_t		primary_send_addr = ctx->sge_list[0].addr;
	int			address_offset = 0;
	int			flows_burst_iter = 0;

	struct dyn_poll_ctx *dyn_ctx = init_dyn_poll_ctx(user_param);
	if (!dyn_ctx) {
		fprintf(stderr, "Failed to allocate dynamic polling context\n");
		return FAILURE;
	}

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ALLOCATE(wc ,struct ibv_wc ,dyn_ctx->config.max);

	/* DURATION 模式初始化：
	 * 使用 SIGALRM 信号控制测试阶段转换
	 * 状态转换：START_STATE -> SAMPLE_STATE -> STOP_SAMPLE_STATE -> END_STATE
	 * margin: 预热时间，在此期间的数据不计入统计
	 * duration: 总持续时间
	 * 采样窗口 = duration - 2*margin (前后各有 margin 时间不计入统计)
	 */
	if (user_param->test_type == DURATION) {
		fprintf(stderr, "[DEBUG] run_iter_bw: DURATION mode, duration=%d seconds, margin=%d seconds\n",
			user_param->duration, user_param->margin);
		duration_param=user_param;
		duration_param->state = START_STATE;
		signal(SIGALRM, catch_alarm);  /* 注册信号处理函数 */
		if (user_param->margin > 0 )
			alarm(user_param->margin);  /* margin 秒后触发，进入 SAMPLE_STATE */
		else
			catch_alarm(0); /* move to next state */

		user_param->iters = 0;  /* DURATION 模式下 iters 用作计数器 */
		fprintf(stderr, "[DEBUG] run_iter_bw: Started timing, will warm up for %d seconds\n",
			user_param->margin);
	}

	if (user_param->duplex && (user_param->use_xrc || user_param->connection_type == DC))
		num_of_qps /= 2;

	/* Will be 0, in case of Duration (look at force_dependencies or in the exp above). */
	tot_iters = (uint64_t)user_param->iters*num_of_qps;

	if (user_param->test_type == DURATION && user_param->state != START_STATE && user_param->margin > 0) {
		fprintf(stderr, "Failed: margin is not long enough (taking samples before warmup ends)\n");
		fprintf(stderr, "Please increase margin or decrease tx_depth\n");
		return_value = FAILURE;
		goto cleaning;
	}

	if (user_param->test_type == ITERATIONS && user_param->noPeak == ON)
		user_param->tposted[0] = get_cycles();

	/* If using rate limiter, calculate gap time between bursts */
	if (user_param->rate_limit_type == SW_RATE_LIMIT ) {
		/* Calculate rate limit in pps */
		switch (user_param->rate_units) {
			case MEGA_BYTE_PS:
				rate_limit_pps = ((double)(user_param->rate_limit) / user_param->size) * 1048576;
				break;
			case GIGA_BIT_PS:
				rate_limit_pps = ((double)(user_param->rate_limit) / (user_param->size * 8)) * 1000000000;
				break;
			case PACKET_PS:
				rate_limit_pps = user_param->rate_limit;
				break;
			default:
				fprintf(stderr, " Failed: Unknown rate limit units\n");
				return_value = FAILURE;
				goto cleaning;
		}
		cpu_mhz = get_cpu_mhz(user_param->cpu_freq_f);
		if (cpu_mhz <= 0) {
			fprintf(stderr, "Failed: couldn't acquire cpu frequency for rate limiter.\n");
		}
		number_of_bursts = (double)rate_limit_pps / (double)user_param->burst_size;
		gap_time = 1000000 * (1.0 / number_of_bursts);
		gap_cycles = cpu_mhz * gap_time;
	}

	/* 主循环：持续 post 发送请求并 poll 完成
	 *
	 * 注意：此函数只在 CLIENT 端执行（对于普通 RDMA WRITE）
	 * SERVER 端不会调用此函数，而是等待 CLIENT 完成
	 *
	 * 循环条件：
	 * - ITERATIONS 模式: 直到发送和完成的总数都达到 tot_iters
	 * - DURATION 模式: 直到状态变为 END_STATE（由 SIGALRM 信号触发）
	 */
	fprintf(stderr, "[DEBUG] run_iter_bw [CLIENT]: Entering main loop, tot_iters=%lu\n", tot_iters);
	fprintf(stderr, "[DEBUG] run_iter_bw [CLIENT]: Will post WRITE requests and poll send CQ\n");

	while (totscnt < tot_iters  || totccnt < tot_iters ||
		(user_param->test_type == DURATION && user_param->state != END_STATE) ) {

		/* 遍历所有 QP，为每个 QP post 消息 */
		for (index =0 ; index < num_of_qps ; index++) {
			if (user_param->rate_limit_type == SW_RATE_LIMIT && is_sending_burst == 0) {
				if (gap_deadline > get_cycles()) {
					/* Go right to cq polling until gap time is over. */
					continue;
				}
				gap_deadline = get_cycles() + gap_cycles;
				is_sending_burst = 1;
				burst_iter = 0;
			}
			while ((ctx->scnt[index] < user_param->iters || user_param->test_type == DURATION) &&
					(ctx->scnt[index] + user_param->post_list) <= (user_param->tx_depth + ctx->ccnt[index]) &&
					!((user_param->rate_limit_type == SW_RATE_LIMIT ) && is_sending_burst == 0)) {

				if (ctx->send_rcredit) {
					uint32_t swindow = ctx->scnt[index] + user_param->post_list - ctx->credit_buf[index];
					if (swindow >= user_param->rx_depth)
						break;
				}
				if (user_param->post_list == 1 && (ctx->scnt[index] % user_param->cq_mod == 0 && user_param->cq_mod > 1)
					&& !(ctx->scnt[index] == (user_param->iters - 1) && user_param->test_type == ITERATIONS)) {

					ctx->wr[index].send_flags &= ~IBV_SEND_SIGNALED;
				}

				if (user_param->noPeak == OFF)
					user_param->tposted[totscnt] = get_cycles();

				if (user_param->test_type == DURATION && user_param->state == END_STATE)
					break;

				/* post_send_method: CLIENT 提交 RDMA WRITE 请求
				 *
				 * 对于 RDMA WRITE 操作，调用 ibv_post_send():
				 * 1. 将 WQE 提交到 CLIENT 端 QP 的发送队列
				 * 2. HCA 硬件读取 WQE，获取以下信息：
				 *    - 本地内存地址和 lkey (从 sge_list)
				 *    - 远程内存地址和 rkey (从 wr.rdma)
				 *    - 数据长度和操作码
				 * 3. HCA 通过 RDMA 网络将数据从 CLIENT 本地内存写入 SERVER 远程内存
				 * 4. 操作完成后，在 CLIENT 的 send CQ 中生成完成事件
				 *    （如果设置了 IBV_SEND_SIGNALED）
				 *
				 * SERVER 端完全无感知：
				 * - 不需要 CPU 参与
				 * - 不需要软件处理
				 * - 数据直接由 HCA 硬件写入内存
				 */
				err = post_send_method(ctx, index, user_param);
				if (err) {
					fprintf(stderr,"[CLIENT] Couldn't post send: qp %d scnt=%lu \n",index,ctx->scnt[index]);
					return_value = FAILURE;
					goto cleaning;
				}

				/* if we have more than single flow and the burst iter is the last one */
				if (user_param->flows != DEF_FLOWS) {
					if (++flows_burst_iter == user_param->flows_burst) {
						flows_burst_iter = 0;
						/* inc the send_flows_index and update the address */
						if (++send_flows_index == user_param->flows)
							send_flows_index = 0;
						address_offset = send_flows_index * ctx->flow_buff_size;
						ctx->sge_list[0].addr = primary_send_addr + address_offset;
					}
				}

				/* in multiple flow scenarios we will go to next cycle buffer address in the main buffer*/
				if (user_param->post_list == 1 && user_param->size <= (ctx->cycle_buffer / 2)) {
						increase_loc_addr(ctx->wr[index].sg_list,user_param->size, ctx->scnt[index],
								ctx->my_addr[index] + address_offset , 0, ctx->cache_line_size,
								ctx->cycle_buffer);

					if (user_param->verb != SEND) {
						increase_rem_addr(&ctx->wr[index], user_param->size,
								ctx->scnt[index], ctx->rem_addr[index], user_param->verb,
								ctx->cache_line_size, ctx->cycle_buffer);
					}
				}

				ctx->scnt[index] += user_param->post_list;
				totscnt += user_param->post_list;

				/* ask for completion on this wr */
				if (user_param->post_list == 1 &&
						(ctx->scnt[index]%user_param->cq_mod == user_param->cq_mod - 1 ||
							(user_param->test_type == ITERATIONS && ctx->scnt[index] == user_param->iters - 1))) {
						ctx->wr[index].send_flags |= IBV_SEND_SIGNALED;
				}

				/* Check if a full burst was sent. */
				if (user_param->rate_limit_type == SW_RATE_LIMIT) {
					burst_iter += user_param->post_list;
					if (burst_iter >= user_param->burst_size) {
						is_sending_burst = 0;
					}
				}
			}
		}

		/* Poll 发送完成队列，获取已完成的 RDMA WRITE 操作
		 *
		 * CLIENT 端 polling 行为：
		 * - 调用 ibv_poll_cq(ctx->send_cq) 检查 WRITE 操作是否完成
		 * - 完成事件 (CQE) 包含：
		 *   - wc.status: 操作状态（IBV_WC_SUCCESS 表示成功）
		 *   - wc.wr_id: 标识哪个 WQE 完成了
		 * - 完成事件表示数据已成功从 CLIENT 写入 SERVER 的远程内存
		 *
		 * 关键点：
		 * - 只需 poll CLIENT 的 send CQ
		 * - 不需要 poll recv CQ（因为是单边操作）
		 * - SERVER 端完全不需要 poll CQ
		 * - ne 返回本次 poll 到的完成数量
		 */
		if (totccnt < tot_iters || (user_param->test_type == DURATION &&  totccnt < totscnt)) {
				/* Make sure all completions from previous event were polled before waiting for another */
				if (user_param->use_event && ne == 0) {
					if (ctx_notify_events(ctx->send_channel)) {
						fprintf(stderr, "Couldn't request CQ notification\n");
						return_value = FAILURE;
						goto cleaning;
					}
				}
				/* Dynamic CQE poll size adaptation
				 * 动态调整每次 poll 的 CQE 数量以优化性能
				 */
				ne = poll_completions(
					ctx->send_cq,
					wc,
					dyn_ctx,
					totccnt,
					&user_param->dynamic_cqe_poll);

				if (ne > 0) {
					for (i = 0; i < ne; i++) {
						qp_index = (int)get_wr_id_qp_index(wc[i].wr_id);

						if (wc[i].status != IBV_WC_SUCCESS) {
							NOTIFY_COMP_ERROR_SEND(wc[i],totscnt,totccnt);
							return_value = FAILURE;
							goto cleaning;
						}
						int fill = user_param->cq_mod;
						if (user_param->fill_count && ctx->ccnt[qp_index] + user_param->cq_mod > user_param->iters) {
							fill = user_param->iters - ctx->ccnt[qp_index];
						}
						ctx->ccnt[qp_index] += fill;
						totccnt += fill;

						if (user_param->noPeak == OFF) {
							if (totccnt > tot_iters)
								user_param->tcompleted[user_param->iters*num_of_qps - 1] = get_cycles();
							else
								user_param->tcompleted[totccnt-1] = get_cycles();
						}

						if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE) {
							if (user_param->report_per_port) {
								user_param->iters_per_port[user_param->port_by_qp[qp_index]] += user_param->cq_mod;
							}
							user_param->iters += user_param->cq_mod;
						}
					}

				} else if (ne < 0) {
					fprintf(stderr, "poll CQ failed %d\n",ne);
					return_value = FAILURE;
					goto cleaning;
					}
		}
	}
	if (user_param->noPeak == ON && user_param->test_type == ITERATIONS)
		user_param->tcompleted[0] = get_cycles();

cleaning:
	free(dyn_ctx);
	free(wc);
	return return_value;
}

/******************************************************************************
 *
 ******************************************************************************/
static inline void set_on_first_rx_packet(struct perftest_parameters *user_param)
{
	if (user_param->test_type == DURATION) {

		duration_param=user_param;
		user_param->iters=0;
		duration_param->state = START_STATE;
		signal(SIGALRM, catch_alarm);
		if (user_param->margin > 0)
			alarm(user_param->margin);
		else
			catch_alarm(0);

	} else if (user_param->tst == BW) {
		user_param->tposted[0] = get_cycles();
	}
}

/******************************************************************************
 *
 ******************************************************************************/
int run_iter_bw_server(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	uint64_t		rcnt = 0;
	int 			ne = 0;
	int			i;
	uint64_t		tot_iters;
	uint64_t                *rcnt_for_qp = NULL;
	uint64_t                *unused_recv_for_qp = NULL;
	uint64_t                *posted_per_qp = NULL;
	struct ibv_wc 		*wc          = NULL;
	struct ibv_recv_wr  	*bad_wr_recv = NULL;
	struct ibv_wc 		*swc = NULL;
	long 			*scredit_for_qp = NULL;
	int 			tot_scredit = 0;
	int 			firstRx = 1;
	int 			return_value = 0;
	int			qp_index;
	int			recv_flows_index = 0;
	uintptr_t		primary_recv_addr = ctx->recv_sge_list[0].addr;
	int			recv_flows_burst = 0;
	int			address_flows_offset =0;

	struct dyn_poll_ctx *dyn_ctx = init_dyn_poll_ctx(user_param);
	if (!dyn_ctx) {
		fprintf(stderr, "Failed to allocate dynamic polling context\n");
		return FAILURE;
	}

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ALLOCATE(wc ,struct ibv_wc ,dyn_ctx->config.max);
	ALLOCATE(swc ,struct ibv_wc ,user_param->tx_depth);

	ALLOCATE(rcnt_for_qp,uint64_t,user_param->num_of_qps);
	memset(rcnt_for_qp,0,sizeof(uint64_t)*user_param->num_of_qps);

	/* Number of receive WQEs available to be posted per QP.
	 * Start with zero as all receive buffers are pre-posted.
	 * Useful for recv_post_list mode. */
	ALLOCATE(unused_recv_for_qp, uint64_t, user_param->num_of_qps);
	memset(unused_recv_for_qp, 0, sizeof(uint64_t) * user_param->num_of_qps);

	ALLOCATE(scredit_for_qp,long,user_param->num_of_qps);
	memset(scredit_for_qp,0,sizeof(long)*user_param->num_of_qps);

	ALLOCATE(posted_per_qp, uint64_t, user_param->num_of_qps);
	for (i = 0; i < user_param->num_of_qps; i++)
		posted_per_qp[i] = ctx->rposted;

	tot_iters = (uint64_t)user_param->iters*user_param->num_of_qps;

	if (user_param->test_type == ITERATIONS) {
		check_alive_data.is_events = user_param->use_event;
		signal(SIGALRM, check_alive);
		alarm(60);
	}

	check_alive_data.g_total_iters = tot_iters;

	while (rcnt < tot_iters || (user_param->test_type == DURATION && user_param->state != END_STATE)) {

		if (user_param->use_event) {
			if (ctx_notify_events(ctx->recv_channel)) {
				fprintf(stderr ," Failed to notify events to CQ\n");
				return_value = FAILURE;
				goto cleaning;
			}
		}

		do {
			if (user_param->test_type == DURATION && user_param->state == END_STATE)
				break;

			/* Dynamic CQE poll size adaptation */
			ne = poll_completions(
				ctx->recv_cq,
				wc,
				dyn_ctx,
				rcnt,
				&user_param->dynamic_cqe_poll);

			if (ne > 0) {
				if (firstRx) {
					set_on_first_rx_packet(user_param);
					firstRx = 0;
				}

				for (i = 0; i < ne; i++) {
					qp_index = (int)get_wr_id_qp_index(wc[i].wr_id);
					if (wc[i].status != IBV_WC_SUCCESS) {

						NOTIFY_COMP_ERROR_RECV(wc[i],rcnt_for_qp[qp_index]);
						return_value = FAILURE;
						goto cleaning;
					}
					rcnt_for_qp[qp_index]++;
					rcnt++;
					unused_recv_for_qp[qp_index]++;
					check_alive_data.current_totrcnt = rcnt;

					if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE) {
						if (user_param->report_per_port) {
							user_param->iters_per_port[user_param->port_by_qp[qp_index]]++;
						}
						user_param->iters++;
					}
					//coverity[uninit_use]
					if ((user_param->test_type==DURATION || posted_per_qp[qp_index] + user_param->recv_post_list <= user_param->iters) &&
					    unused_recv_for_qp[qp_index] >= user_param->recv_post_list && !user_param->use_unsolicited_write) {
						if (user_param->use_srq) {
							if (ibv_post_srq_recv(ctx->srq, &ctx->rwr[qp_index * user_param->recv_post_list], &bad_wr_recv)) {
								fprintf(stderr, "Couldn't post recv SRQ. QP = %d: counter=%lu\n",(int)wc[i].qp_num,rcnt);
								return_value = FAILURE;
								goto cleaning;
							}

						} else {
							if (ibv_post_recv(ctx->qp[qp_index], &ctx->rwr[qp_index * user_param->recv_post_list], &bad_wr_recv)) {
								fprintf(stderr, "Couldn't post recv Qp=%d rcnt=%lu\n",(int)wc[i].qp_num,rcnt_for_qp[qp_index]);
								return_value = 15;
								goto cleaning;
							}
						}
						unused_recv_for_qp[qp_index] -= user_param->recv_post_list;

						if (user_param->flows != DEF_FLOWS) {
							if (++recv_flows_burst == user_param->flows_burst) {
								recv_flows_burst = 0;
								if (++recv_flows_index == user_param->flows)
									recv_flows_index = 0;
								address_flows_offset = recv_flows_index * ctx->cycle_buffer;
								ctx->recv_sge_list[0].addr = primary_recv_addr + address_flows_offset;
							}
						}
						if (SIZE(user_param->connection_type,user_param->size,!(int)user_param->machine) <= (ctx->cycle_buffer / 2) &&
								user_param->recv_post_list == 1) {
							increase_loc_addr(ctx->rwr[(int)get_wr_index(wc[i].wr_id)].sg_list,
									user_param->size,
									posted_per_qp[qp_index],
									ctx->rx_buffer_addr[qp_index] + address_flows_offset,
									user_param->connection_type,ctx->cache_line_size,ctx->cycle_buffer);
						}
						posted_per_qp[qp_index] += user_param->recv_post_list;
					}

					if (ctx->send_rcredit) {
						int credit_cnt = rcnt_for_qp[qp_index]%user_param->rx_depth;

						if (credit_cnt%ctx->credit_cnt == 0) {
							struct ibv_send_wr *bad_wr = NULL;
							int sne = 0, j = 0, swc_qp_index;
							ctx->ctrl_buf[qp_index] = rcnt_for_qp[qp_index];

							while (scredit_for_qp[qp_index] == user_param->tx_depth) {
								sne = ibv_poll_cq(ctx->send_cq,user_param->tx_depth,swc);
								if (sne > 0) {
									for (j = 0; j < sne; j++) {
										swc_qp_index = get_wr_id_qp_index(swc[j].wr_id);
										if (swc[j].status != IBV_WC_SUCCESS) {
											fprintf(stderr, "Poll send CQ error status=%u qp %d credit=%lu scredit=%ld\n",
													swc[j].status,(int)swc[j].qp_num,
													rcnt_for_qp[swc_qp_index],scredit_for_qp[swc_qp_index]);
											return_value = FAILURE;
											goto cleaning;
										}
										scredit_for_qp[swc_qp_index]--;
										tot_scredit--;
									}
								} else if (sne < 0) {
									fprintf(stderr, "Poll send CQ failed ne=%d\n",sne);
									return_value = FAILURE;
									goto cleaning;
								}
							}
							if (ibv_post_send(ctx->qp[qp_index],&ctx->ctrl_wr[qp_index],&bad_wr)) {
								fprintf(stderr,"Couldn't post send qp %d credit = %lu\n",
										(int)wc[i].qp_num,rcnt_for_qp[qp_index]);
								return_value = FAILURE;
								goto cleaning;
							}
							scredit_for_qp[qp_index]++;
							tot_scredit++;
						}
					}
				}
			}

		} while (ne > 0);

		if (ne < 0) {
			fprintf(stderr, "Poll Receive CQ failed %d\n", ne);
			return_value = FAILURE;
			goto cleaning;
		}
		else if (ne == 0) {
			if (check_alive_data.to_exit) {
				user_param->check_alive_exited = 1;
				return_value = FAILURE;
				goto cleaning;
			}
		}

	}
	if (user_param->test_type == ITERATIONS)
		user_param->tcompleted[0] = get_cycles();

cleaning:
	if (ctx->send_rcredit) {
		if (clean_scq_credit(tot_scredit, ctx, user_param))
			return_value = FAILURE;
	}
	free(dyn_ctx);
	check_alive_data.last_totrcnt=0;
	free(wc);
	free(rcnt_for_qp);
	free(swc);
	free(scredit_for_qp);
	free(unused_recv_for_qp);
	free(posted_per_qp);

	return return_value;
}
/******************************************************************************
 *
 ******************************************************************************/

// Signal flag and handler for proper exit when running infinitely
volatile sig_atomic_t sigint_flag = 0;

void handle_sigint(int sig) {
    sigint_flag = 1;
}

int run_iter_bw_infinitely(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	uint64_t		totscnt = 0;
	uint64_t		totccnt = 0;
	int 			i = 0;
	int 			index, ne;
	int 			err = 0;
	int			qp_index;
	uint64_t		*scnt_for_qp = NULL;
	struct ibv_wc 		*wc = NULL;
	int 			num_of_qps = user_param->num_of_qps;
	int 			return_value = 0;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	struct dyn_poll_ctx *dyn_ctx = init_dyn_poll_ctx(user_param);
	if (!dyn_ctx) {
		fprintf(stderr, "Failed to allocate dynamic polling context\n");
		return FAILURE;
	}

	ALLOCATE(wc ,struct ibv_wc ,dyn_ctx->config.max);
	ALLOCATE(scnt_for_qp,uint64_t,user_param->num_of_qps);
	memset(scnt_for_qp,0,sizeof(uint64_t)*user_param->num_of_qps);

	duration_param=user_param;

	pthread_t print_thread;
	if (pthread_create(&print_thread, NULL, &handle_signal_print_thread,(void*)&user_param->duration) != 0){
		printf("Fail to create thread \n");
		free(wc);
		free(scnt_for_qp);
		return FAILURE;
	}

	if (!user_param->duplex && user_param->verb != WRITE_IMM && user_param->verb != SEND){
		signal(SIGINT, handle_sigint);
	}

	user_param->iters = 0;
	user_param->last_iters = 0;

	/* Will be 0, in case of Duration (look at force_dependencies or in the exp above) */
	if (user_param->duplex && (user_param->use_xrc || user_param->connection_type == DC))
		num_of_qps /= 2;

	user_param->tposted[0] = get_cycles();

	/* main loop for posting */
	while (1) {
	/* main loop to run over all the qps and post each time n messages */
		for (index = 0 ; index < num_of_qps ; index++) {

			while ((ctx->scnt[index] - ctx->ccnt[index] + user_param->post_list) <= user_param->tx_depth) {
				if (ctx->send_rcredit) {
					uint32_t swindow = scnt_for_qp[index] + user_param->post_list - ctx->credit_buf[index];
					if (swindow >= user_param->rx_depth)
						break;
				}

				if (user_param->post_list == 1 && (ctx->scnt[index] % user_param->cq_mod == 0 && user_param->cq_mod > 1)) {
					ctx->wr[index].send_flags &= ~IBV_SEND_SIGNALED;
				}

				err = post_send_method(ctx, index, user_param);
				if (err) {
					fprintf(stderr,"Couldn't post send: %d scnt=%lu \n",index,ctx->scnt[index]);
					return_value = FAILURE;
					goto cleaning;
				}
				ctx->scnt[index] += user_param->post_list;
				scnt_for_qp[index] += user_param->post_list;
				totscnt += user_param->post_list;

				/* ask for completion on this wr */
				if (user_param->post_list == 1 &&
						(ctx->scnt[index]%user_param->cq_mod == user_param->cq_mod - 1 ||
							(user_param->test_type == ITERATIONS && ctx->scnt[index] == user_param->iters - 1))) {
					ctx->wr[index].send_flags |= IBV_SEND_SIGNALED;
				}
			}
		}
		if (totccnt < totscnt) {
			ne = poll_completions(
				ctx->send_cq,
				wc,
				dyn_ctx,
				totccnt,
				&user_param->dynamic_cqe_poll);

			if (ne > 0) {

				for (i = 0; i < ne; i++) {
					qp_index = (int)get_wr_id_qp_index(wc[i].wr_id);
					if (wc[i].status != IBV_WC_SUCCESS) {
						NOTIFY_COMP_ERROR_SEND(wc[i],ctx->scnt[qp_index],ctx->scnt[qp_index]);
						return_value = FAILURE;
						goto cleaning;
					}
					user_param->iters += user_param->cq_mod;
					totccnt += user_param->cq_mod;
					ctx->ccnt[qp_index] += user_param->cq_mod;
				}

			} else if (ne < 0) {
				fprintf(stderr, "poll CQ failed %d\n",ne);
				return_value = FAILURE;
				goto cleaning;
			}
		}

		if (sigint_flag) {
			printf("\n User stopped traffic\n");
			goto cleaning;
		}
	}
cleaning:
	free(dyn_ctx);
	free(scnt_for_qp);
	free(wc);
	return return_value;
}

/******************************************************************************
 *
 ******************************************************************************/
int run_iter_bw_infinitely_server(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	int 			i,ne;
	struct ibv_wc 		*wc          = NULL;
	struct ibv_wc 		*swc         = NULL;
	struct ibv_recv_wr 	*bad_wr_recv = NULL;
	uint64_t                *rcnt_for_qp = NULL;
	uint64_t                *ccnt_for_qp = NULL;
	uint64_t                *unused_recv_for_qp = NULL;
	int                     *scredit_for_qp = NULL;
	int 			return_value = 0;
	int 			qp_index;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	struct dyn_poll_ctx *dyn_ctx = init_dyn_poll_ctx(user_param);
	if (!dyn_ctx) {
		fprintf(stderr, "Failed to allocate dynamic polling context\n");
		return FAILURE;
	}

	ALLOCATE(wc ,struct ibv_wc ,dyn_ctx->config.max);
	ALLOCATE(swc ,struct ibv_wc ,user_param->tx_depth);

	ALLOCATE(rcnt_for_qp,uint64_t,user_param->num_of_qps);
	memset(rcnt_for_qp,0,sizeof(uint64_t)*user_param->num_of_qps);

	ALLOCATE(ccnt_for_qp,uint64_t,user_param->num_of_qps);
	memset(ccnt_for_qp,0,sizeof(uint64_t)*user_param->num_of_qps);

	/* Number of receive WQEs available to be posted per QP.
	 * Start with zero as all receive buffers are pre-posted.
	 * Useful for recv_post_list mode. */
	ALLOCATE(unused_recv_for_qp, uint64_t, user_param->num_of_qps);
	memset(unused_recv_for_qp, 0, sizeof(uint64_t) * user_param->num_of_qps);

	ALLOCATE(scredit_for_qp,int,user_param->num_of_qps);
	memset(scredit_for_qp,0,sizeof(int)*user_param->num_of_qps);

	duration_param=user_param;
	pthread_t print_thread;
	if (pthread_create(&print_thread, NULL, &handle_signal_print_thread, (void *)&user_param->duration) != 0)
	{
		printf("Fail to create thread \n");
		return_value = FAILURE;
		goto cleaning;
	}

	user_param->iters = 0;
	user_param->last_iters = 0;
	user_param->tposted[0] = get_cycles();

	while (1) {

		ne = poll_completions(
			ctx->recv_cq,
			wc,
			dyn_ctx,
			user_param->iters,
			&user_param->dynamic_cqe_poll);

		if (ne > 0) {

			for (i = 0; i < ne; i++) {
				qp_index = (int)get_wr_id_qp_index(wc[i].wr_id);
				if (wc[i].status != IBV_WC_SUCCESS) {
					fprintf(stderr,"A completion with Error in run_infinitely_bw_server function");
					return_value = FAILURE;
					goto cleaning;
				}
				user_param->iters++;
				unused_recv_for_qp[qp_index]++;
				if (unused_recv_for_qp[qp_index] >= user_param->recv_post_list && !user_param->use_unsolicited_write) {
					if (user_param->use_srq) {
						if (ibv_post_srq_recv(ctx->srq, &ctx->rwr[qp_index * user_param->recv_post_list],&bad_wr_recv)) {
							fprintf(stderr, "Couldn't post recv SRQ. QP = %d:\n",(int)wc[i].qp_num);
							return_value = FAILURE;
							goto cleaning;
						}

					} else {
						if (ibv_post_recv(ctx->qp[qp_index],&ctx->rwr[qp_index * user_param->recv_post_list],&bad_wr_recv)) {
							fprintf(stderr, "Couldn't post recv Qp=%d\n",(int)wc[i].qp_num);
							return_value = 15;
							goto cleaning;
						}
					}
					unused_recv_for_qp[qp_index] -= user_param->recv_post_list;
				}

				if (!user_param->use_srq && ctx->send_rcredit) {
					rcnt_for_qp[qp_index]++;
					scredit_for_qp[qp_index]++;

					if (scredit_for_qp[qp_index] == ctx->credit_cnt) {
						struct ibv_send_wr *bad_wr = NULL;
						ctx->ctrl_buf[qp_index] = rcnt_for_qp[qp_index];

						while (ccnt_for_qp[qp_index] == user_param->tx_depth) {
							int sne, j = 0, swc_qp_index;

							sne = ibv_poll_cq(ctx->send_cq,user_param->tx_depth,swc);
							if (sne > 0) {
								for (j = 0; j < sne; j++) {
									swc_qp_index = get_wr_id_qp_index(swc[j].wr_id);
									if (swc[j].status != IBV_WC_SUCCESS) {
										fprintf(stderr, "Poll send CQ error status=%u qp %d credit=%lu scredit=%lu\n",
												swc[j].status,(int)swc[j].qp_num,
												rcnt_for_qp[swc_qp_index],ccnt_for_qp[swc_qp_index]);
										return_value = FAILURE;
										goto cleaning;
									}
									ccnt_for_qp[swc_qp_index]--;
								}

							} else if (sne < 0) {
								fprintf(stderr, "Poll send CQ failed ne=%d\n",sne);
								return_value = FAILURE;
								goto cleaning;
							}
						}
						if (ibv_post_send(ctx->qp[qp_index],&ctx->ctrl_wr[qp_index],&bad_wr)) {
							fprintf(stderr,"Couldn't post send qp %d credit=%lu\n",
									(int)wc[i].qp_num,rcnt_for_qp[qp_index]);
							return_value = FAILURE;
							goto cleaning;
						}
						ccnt_for_qp[qp_index]++;
						scredit_for_qp[qp_index] = 0;
					}
				}
			}

		} else if (ne < 0) {
			fprintf(stderr, "Poll Receive CQ failed %d\n", ne);
			return_value = FAILURE;
			goto cleaning;
		}
	}

cleaning:
	free(dyn_ctx);
	free(wc);
	free(swc);
	free(rcnt_for_qp);
	free(ccnt_for_qp);
	free(unused_recv_for_qp);
	free(scredit_for_qp);
	return return_value;
}

/******************************************************************************
 *
 ******************************************************************************/
int run_iter_bi(struct pingpong_context *ctx,
		struct perftest_parameters *user_param)  {

	uint64_t 		totscnt    = 0;
	uint64_t 		totccnt    = 0;
	uint64_t 		totrcnt    = 0;
	int 			i,index      = 0;
	int			send_ne = 0;
	int			recv_ne = 0;
	int 			err = 0;
	uint64_t 		*rcnt_for_qp = NULL;
	uint64_t 		*unused_recv_for_qp = NULL;
	uint64_t		*posted_per_qp = NULL;
	uint64_t 		tot_iters = 0;
	uint64_t 		iters = 0;
	int 			tot_scredit = 0;
	int 			*scredit_for_qp = NULL;
	struct ibv_wc 		*wc = NULL;
	struct ibv_wc 		*wc_tx = NULL;
	struct ibv_recv_wr 	*bad_wr_recv = NULL;
	int 			num_of_qps = user_param->num_of_qps;
	/* This is to ensure SERVER will not start to send packets before CLIENT start the test. */
	int 			before_first_rx = ON;
	int 			return_value = 0;
	int 			qp_index;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ALLOCATE(wc_tx,struct ibv_wc,user_param->cqe_poll);
	ALLOCATE(rcnt_for_qp,uint64_t,user_param->num_of_qps);
	ALLOCATE(scredit_for_qp,int,user_param->num_of_qps);
	ALLOCATE(wc,struct ibv_wc,user_param->rx_depth);

	memset(rcnt_for_qp,0,sizeof(uint64_t)*user_param->num_of_qps);
	memset(scredit_for_qp,0,sizeof(int)*user_param->num_of_qps);

	/* Number of receive WQEs available to be posted per QP.
	 * Start with zero as all receive buffers are pre-posted.
	 * Useful for recv_post_list mode. */
	ALLOCATE(unused_recv_for_qp, uint64_t, user_param->num_of_qps);
	memset(unused_recv_for_qp, 0, sizeof(uint64_t) * user_param->num_of_qps);

	ALLOCATE(posted_per_qp, uint64_t, user_param->num_of_qps);
	for (i = 0; i < user_param->num_of_qps; i++)
		posted_per_qp[i] = ctx->rposted;

	if (user_param->noPeak == ON)
		user_param->tposted[0] = get_cycles();

	/* This is a very important point. Since this function do RX and TX
	   in the same time, we need to give some priority to RX to avoid
	   deadlock in UC/UD test scenarios (Recv WQEs depleted due to fast TX) */
	if (user_param->machine == CLIENT) {

		before_first_rx = OFF;
		if (user_param->test_type == DURATION) {
			duration_param=user_param;
			user_param->iters=0;
			duration_param->state = START_STATE;
			signal(SIGALRM, catch_alarm);

			if (user_param->margin > 0 )
				alarm(user_param->margin);
			else
				catch_alarm(0); /* move to next state */
		}
	}

	if (user_param->test_type == ITERATIONS) {
		check_alive_data.is_events = user_param->use_event;
		signal(SIGALRM, check_alive);
		alarm(60);
	}


	if(user_param->duplex && (user_param->use_xrc || user_param->connection_type == DC))
		num_of_qps /= 2;

	tot_iters = (uint64_t)user_param->iters*num_of_qps;
	iters=user_param->iters;
	check_alive_data.g_total_iters = tot_iters;

	while ((user_param->test_type == DURATION && user_param->state != END_STATE) ||
							totccnt < tot_iters || totrcnt < tot_iters ) {

		for (index=0; index < num_of_qps; index++) {
			while (before_first_rx == OFF && (ctx->scnt[index] < iters || user_param->test_type == DURATION) &&
					((ctx->scnt[index] + scredit_for_qp[index] - ctx->ccnt[index] + user_param->post_list) <= user_param->tx_depth)) {
				if (ctx->send_rcredit) {
					uint32_t swindow = ctx->scnt[index] + user_param->post_list - ctx->credit_buf[index];
					if (swindow >= user_param->rx_depth)
						break;
				}
				if (user_param->post_list == 1 && (ctx->scnt[index] % user_param->cq_mod == 0 && user_param->cq_mod > 1)
					&& !(ctx->scnt[index] == (user_param->iters - 1) && user_param->test_type == ITERATIONS)) {
					ctx->wr[index].send_flags &= ~IBV_SEND_SIGNALED;
				}
				if (user_param->noPeak == OFF)
					user_param->tposted[totscnt] = get_cycles();

				if (user_param->test_type == DURATION && duration_param->state == END_STATE)
					break;

				err = post_send_method(ctx, index, user_param);

				if (err) {
					fprintf(stderr,"Couldn't post send: qp %d scnt=%lu \n",index,ctx->scnt[index]);
					return_value = FAILURE;
					goto cleaning;
				}

				if (user_param->post_list == 1 && user_param->size <= (ctx->cycle_buffer / 2)) {
					increase_loc_addr(ctx->wr[index].sg_list,user_param->size,ctx->scnt[index],
						ctx->my_addr[index],0,ctx->cache_line_size,ctx->cycle_buffer);
				}

				ctx->scnt[index] += user_param->post_list;
				totscnt += user_param->post_list;

				if (user_param->post_list == 1 &&
					(ctx->scnt[index]%user_param->cq_mod == user_param->cq_mod - 1 ||
						(user_param->test_type == ITERATIONS && ctx->scnt[index] == iters-1))) {

					ctx->wr[index].send_flags |= IBV_SEND_SIGNALED;
				}
			}
		}
		/* Make sure all completions from previous event were polled before waiting for another */
		if (user_param->use_event && recv_ne == 0 && send_ne == 0) {
			if (ctx_notify_send_recv_events(ctx)) {
				return_value = FAILURE;
				goto cleaning;
			}
		}

		recv_ne = ibv_poll_cq(ctx->recv_cq, user_param->rx_depth, wc);
		if (recv_ne > 0) {

			if (user_param->machine == SERVER && before_first_rx == ON) {
				before_first_rx = OFF;
				if (user_param->test_type == DURATION) {
					duration_param=user_param;
					user_param->iters=0;
					duration_param->state = START_STATE;
					signal(SIGALRM, catch_alarm);
					if (user_param->margin > 0 )
						alarm(user_param->margin);
					else
						catch_alarm(0); /* move to next state */
				}
			}

			for (i = 0; i < recv_ne; i++) {
				qp_index = (int)get_wr_id_qp_index(wc[i].wr_id);
				if (wc[i].status != IBV_WC_SUCCESS) {
					NOTIFY_COMP_ERROR_RECV(wc[i],totrcnt);
					return_value = FAILURE;
					goto cleaning;
				}

				rcnt_for_qp[qp_index]++;
				unused_recv_for_qp[qp_index]++;
				totrcnt++;
				check_alive_data.current_totrcnt = totrcnt;

				if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE) {
					if (user_param->report_per_port) {
						user_param->iters_per_port[user_param->port_by_qp[qp_index]]++;
					}
					user_param->iters++;
				}

				if ((user_param->test_type==DURATION || posted_per_qp[qp_index] + user_param->recv_post_list <= user_param->iters) &&
				    unused_recv_for_qp[qp_index] >= user_param->recv_post_list && !user_param->use_unsolicited_write) {
					if (user_param->use_srq) {
						if (ibv_post_srq_recv(ctx->srq, &ctx->rwr[qp_index * user_param->recv_post_list],&bad_wr_recv)) {
							fprintf(stderr, "Couldn't post recv SRQ. QP = %d: counter=%d\n",(int)wc[i].qp_num,(int)totrcnt);
							return_value = FAILURE;
							goto cleaning;
						}

					} else {

						if (ibv_post_recv(ctx->qp[qp_index],&ctx->rwr[qp_index * user_param->recv_post_list],&bad_wr_recv)) {
							fprintf(stderr, "Couldn't post recv Qp=%d rcnt=%lu\n",(int)wc[i].qp_num,rcnt_for_qp[qp_index]);
							return_value = 15;
							goto cleaning;
						}
					}
					unused_recv_for_qp[qp_index] -= user_param->recv_post_list;
					//coverity[uninit_use]

					if (SIZE(user_param->connection_type,user_param->size,!(int)user_param->machine) <= (ctx->cycle_buffer / 2) &&
							user_param->recv_post_list == 1) {
						increase_loc_addr(ctx->rwr[get_wr_index(wc[i].wr_id)].sg_list,
								user_param->size,
								posted_per_qp[qp_index],
								ctx->rx_buffer_addr[qp_index],user_param->connection_type,
								ctx->cache_line_size,ctx->cycle_buffer);
					}
					posted_per_qp[qp_index] += user_param->recv_post_list;
				}
				if (ctx->send_rcredit) {
					int credit_cnt = rcnt_for_qp[qp_index]%user_param->rx_depth;

					if (credit_cnt%ctx->credit_cnt == 0) {
						int sne = 0;
						struct ibv_wc credit_wc;
						struct ibv_send_wr *bad_wr = NULL;
						ctx->ctrl_buf[qp_index] = rcnt_for_qp[qp_index];

						while ((ctx->scnt[qp_index] + scredit_for_qp[qp_index]) >= (user_param->tx_depth + ctx->ccnt[qp_index])) {
							sne = ibv_poll_cq(ctx->send_cq, 1, &credit_wc);
							if (sne > 0) {
								if (credit_wc.status != IBV_WC_SUCCESS) {
									fprintf(stderr, "Poll send CQ error status=%u qp %d credit=%lu scredit=%d\n",
											credit_wc.status,(int)credit_wc.qp_num,
											rcnt_for_qp[get_wr_id_qp_index(credit_wc.wr_id)],scredit_for_qp[get_wr_id_qp_index(credit_wc.wr_id)]);
									return_value = FAILURE;
									goto cleaning;
								}

								//coverity[uninit_use]
								if (credit_wc.opcode == IBV_WC_RDMA_WRITE) {
									scredit_for_qp[get_wr_id_qp_index(credit_wc.wr_id)]--;
									tot_scredit--;
								} else  {
									totccnt += user_param->cq_mod;
									ctx->ccnt[(int)get_wr_id_qp_index(credit_wc.wr_id)] += user_param->cq_mod;

									if (user_param->noPeak == OFF) {
										if ((user_param->test_type == ITERATIONS && (totccnt > tot_iters)))
											user_param->tcompleted[tot_iters - 1] = get_cycles();
										else
											user_param->tcompleted[totccnt-1] = get_cycles();
									}
									if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE)
										user_param->iters += user_param->cq_mod;
								}
							} else if (sne < 0) {
								fprintf(stderr, "Poll send CQ ne=%d\n",sne);
								return_value = FAILURE;
								goto cleaning;
							}
						}
						if (ibv_post_send(ctx->qp[qp_index],&ctx->ctrl_wr[qp_index],&bad_wr)) {
							fprintf(stderr,"Couldn't post send: qp%u credit=%lu\n",wc[i].qp_num,rcnt_for_qp[qp_index]);
							return_value = FAILURE;
							goto cleaning;
						}
						scredit_for_qp[qp_index]++;
						tot_scredit++;
					}
				}
			}

		} else if (recv_ne < 0) {
			fprintf(stderr, "poll CQ failed %d\n", recv_ne);
			return_value = FAILURE;
			goto cleaning;
		}
		else {
			if (check_alive_data.to_exit) {
				user_param->check_alive_exited = 1;
				return_value = FAILURE;
				goto cleaning;
			}
		}

		send_ne = ibv_poll_cq(ctx->send_cq, user_param->cqe_poll, wc_tx);

		if (send_ne > 0) {
			for (i = 0; i < send_ne; i++) {
				if (wc_tx[i].status != IBV_WC_SUCCESS) {
					NOTIFY_COMP_ERROR_SEND(wc_tx[i],totscnt,totccnt);
					return_value = FAILURE;
					goto cleaning;
				}

				if (wc_tx[i].opcode == IBV_WC_RDMA_WRITE && user_param->verb != WRITE_IMM) {
					if (!ctx->send_rcredit) {
						fprintf(stderr, "Polled RDMA_WRITE completion without recv credit request\n");
						return_value = FAILURE;
						goto cleaning;
					}
					scredit_for_qp[get_wr_id_qp_index(wc_tx[i].wr_id)]--;
					tot_scredit--;
				} else  {
					totccnt += user_param->cq_mod;
					ctx->ccnt[(int)get_wr_id_qp_index(wc_tx[i].wr_id)] += user_param->cq_mod;

					if (user_param->noPeak == OFF) {

						if ((user_param->test_type == ITERATIONS && (totccnt > tot_iters)))
							user_param->tcompleted[tot_iters - 1] = get_cycles();
						else
							user_param->tcompleted[totccnt-1] = get_cycles();
					}

					if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE) {
						if (user_param->report_per_port) {
							user_param->iters_per_port[user_param->port_by_qp[(int)get_wr_id_qp_index(wc[i].wr_id)]] += user_param->cq_mod;
						}
						user_param->iters += user_param->cq_mod;
					}
				}
			}

		} else if (send_ne < 0) {
			fprintf(stderr, "poll CQ failed %d\n", send_ne);
			return_value = FAILURE;
			goto cleaning;
		}
	}

	if (user_param->noPeak == ON && user_param->test_type == ITERATIONS) {
		user_param->tcompleted[0] = get_cycles();
	}

	if (ctx->send_rcredit) {
		if (clean_scq_credit(tot_scredit, ctx, user_param)) {
			return_value = FAILURE;
			goto cleaning;
		}
	}

cleaning:
	check_alive_data.last_totrcnt=0;
	free(rcnt_for_qp);
	free(scredit_for_qp);
	free(wc);
	free(wc_tx);
	free(posted_per_qp);
	free(unused_recv_for_qp);
	return return_value;
}

/******************************************************************************
 *
 ******************************************************************************/
int run_iter_lat_write(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	uint64_t                scnt = 0;
	uint64_t                ccnt = 0;
	uint64_t                rcnt = 0;
	int                     ne;
	int			err = 0;
	int 			poll_buf_offset = 0;
	volatile char           *poll_buf = NULL;
	volatile char           *post_buf = NULL;


	struct ibv_wc           wc;

	int 			cpu_mhz = get_cpu_mhz(user_param->cpu_freq_f);
	int 			total_gap_cycles = user_param->latency_gap * cpu_mhz;
	cycles_t 		end_cycle, start_gap;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ctx->wr[0].sg_list->length = user_param->size;
	ctx->wr[0].send_flags = IBV_SEND_SIGNALED;

	if (user_param->size <= user_param->inline_size) {
		ctx->wr[0].send_flags |= IBV_SEND_INLINE;
	}


	if((user_param->use_xrc || user_param->connection_type == DC))
		poll_buf_offset = 1;

	post_buf = (char*)ctx->buf[0] + user_param->size - 1;
	poll_buf = (char*)ctx->buf[0] + (user_param->num_of_qps + poll_buf_offset)*BUFF_SIZE(ctx->size, ctx->cycle_buffer) + user_param->size - 1;

	/* Duration support in latency tests. */
	if (user_param->test_type == DURATION) {
		duration_param=user_param;
		duration_param->state = START_STATE;
		signal(SIGALRM, catch_alarm);
		user_param->iters = 0;
		if (user_param->margin > 0)
			alarm(user_param->margin);
		else
			catch_alarm(0);
	}

	/* Done with setup. Start the test. */
	while (scnt < user_param->iters || ccnt < user_param->iters || rcnt < user_param->iters
			|| ((user_param->test_type == DURATION && user_param->state != END_STATE))) {

		if ((rcnt < user_param->iters || user_param->test_type == DURATION) && !(scnt < 1 && user_param->machine == SERVER)) {
			rcnt++;
			while (*poll_buf != (char)rcnt && user_param->state != END_STATE);
		}

		if (scnt < user_param->iters || user_param->test_type == DURATION) {

			if (user_param->latency_gap) {
				start_gap = get_cycles();
				end_cycle = start_gap + total_gap_cycles;
				while (get_cycles() < end_cycle) {
					continue;
				}
			}

			if (user_param->test_type == ITERATIONS)
				user_param->tposted[scnt] = get_cycles();

			*post_buf = (char)++scnt;

			err = post_send_method(ctx, 0, user_param);

			if (err) {
				fprintf(stderr,"Couldn't post send: scnt=%lu\n",scnt);
				return 1;
			}
		}

		if (user_param->test_type == DURATION && user_param->state == END_STATE)
			break;

		if (ccnt < user_param->iters || user_param->test_type == DURATION) {

			do { ne = ibv_poll_cq(ctx->send_cq, 1, &wc); } while (ne == 0 && !(user_param->test_type == DURATION && user_param->state == END_STATE));

			if(ne > 0) {

				if (wc.status != IBV_WC_SUCCESS) {
					//coverity[uninit_use_in_call]
					NOTIFY_COMP_ERROR_SEND(wc,scnt,ccnt);
					return 1;
				}

				ccnt++;
				if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE)
					user_param->iters++;

			} else if (ne < 0) {
				fprintf(stderr, "poll CQ failed %d\n", ne);
				return FAILURE;
			}
		}
	}
	return 0;
}

/******************************************************************************
 *
 ******************************************************************************/
int run_iter_lat_write_imm(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	uint64_t                scnt = 0;
	uint64_t                ccnt = 0;
	uint64_t                rcnt = 0;
	int                     ne = 0;
	int			err = 0;

	int 			size_per_qp = (user_param->use_srq) ?
					user_param->rx_depth/user_param->num_of_qps : user_param->rx_depth;
	struct ibv_wc           wc;
	struct ibv_recv_wr 	*bad_wr_recv = NULL;


	int 			cpu_mhz = get_cpu_mhz(user_param->cpu_freq_f);
	int 			total_gap_cycles = user_param->latency_gap * cpu_mhz;
	cycles_t 		end_cycle, start_gap;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ctx->wr[0].sg_list->length = user_param->size;
	ctx->wr[0].send_flags = IBV_SEND_SIGNALED;

	if (user_param->size <= user_param->inline_size) {
		ctx->wr[0].send_flags |= IBV_SEND_INLINE;
	}

	/* Duration support in latency tests. */
	if (user_param->test_type == DURATION) {
		duration_param=user_param;
		duration_param->state = START_STATE;
		signal(SIGALRM, catch_alarm);
		user_param->iters = 0;
		if (user_param->margin > 0)
			alarm(user_param->margin);
		else
			catch_alarm(0);
	}

	/* Done with setup. Start the test. */
	while (scnt < user_param->iters || ccnt < user_param->iters || rcnt < user_param->iters
			|| ((user_param->test_type == DURATION && user_param->state != END_STATE))) {

		if ((rcnt < user_param->iters || user_param->test_type == DURATION) && !(scnt < 1 && user_param->machine == SERVER)) {
			rcnt++;

			if (user_param->use_event) {
				if (ctx_notify_events(ctx->recv_channel)) {
					fprintf(stderr , " Failed to notify events to CQ\n");
					return 1;
				}
			}

			/* Poll for a completion */
			do { ne = ibv_poll_cq(ctx->recv_cq, 1, &wc); } while (!user_param->use_event && ne == 0 && !(user_param->test_type == DURATION && user_param->state == END_STATE));
			if (ne > 0) {
				if (wc.status != IBV_WC_SUCCESS) {
					//coverity[uninit_use_in_call]
					NOTIFY_COMP_ERROR_SEND(wc,scnt,ccnt);
					return 1;
				}

				/*if we're in duration mode or there
				 * is enough space in the rx_depth,
				 * post that you received a packet.
				 */
				if ((user_param->test_type == DURATION || (rcnt + size_per_qp <= user_param->iters)) &&
				    !user_param->use_unsolicited_write) {
					if (user_param->use_srq) {
						if (ibv_post_srq_recv(ctx->srq, &ctx->rwr[get_wr_index(wc.wr_id)], &bad_wr_recv)) {
							fprintf(stderr, "Couldn't post recv SRQ. QP = %d: counter=%lu\n",(int)wc.qp_num, rcnt);
							return 1;
						}
					} else {
						if (ibv_post_recv(ctx->qp[get_wr_id_qp_index(wc.wr_id)], &ctx->rwr[get_wr_index(wc.wr_id)], &bad_wr_recv)) {
							fprintf(stderr, "Couldn't post recv: rcnt=%lu\n", rcnt);
							return 15;
						}
					}
				}
			} else if (ne < 0) {
				fprintf(stderr, "poll CQ failed %d\n", ne);
				return FAILURE;
			}
		}

		if (scnt < user_param->iters || user_param->test_type == DURATION) {

			if (user_param->latency_gap) {
				start_gap = get_cycles();
				end_cycle = start_gap + total_gap_cycles;
				while (get_cycles() < end_cycle) {
					continue;
				}
			}

			if (user_param->test_type == ITERATIONS)
				user_param->tposted[scnt] = get_cycles();

			++scnt;
			err = post_send_method(ctx, 0, user_param);

			if (err) {
				fprintf(stderr,"Couldn't post send: scnt=%lu\n",scnt);
				return 1;
			}
		}

		if (user_param->test_type == DURATION && user_param->state == END_STATE)
			break;

		if (ccnt < user_param->iters || user_param->test_type == DURATION) {

			if (user_param->use_event && ne == 0) {
				if (ctx_notify_events(ctx->send_channel)) {
					fprintf(stderr, "Couldn't request CQ notification\n");
					return 1;
				}
			}

			do { ne = ibv_poll_cq(ctx->send_cq, 1, &wc); } while (ne == 0);

			if(ne > 0) {

				if (wc.status != IBV_WC_SUCCESS) {
					//coverity[uninit_use_in_call]
					NOTIFY_COMP_ERROR_SEND(wc,scnt,ccnt);
					return 1;
				}

				ccnt++;
				if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE)
					user_param->iters++;

			} else if (ne < 0) {
				fprintf(stderr, "poll CQ failed %d\n", ne);
				return FAILURE;
			}
		}
	}
	return 0;
}

/******************************************************************************
 *
 ******************************************************************************/
int run_iter_lat(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	uint64_t	scnt = 0;
	int 		ne;
	int		err = 0;
	struct 		ibv_wc wc;
	int 		cpu_mhz = get_cpu_mhz(user_param->cpu_freq_f);
	int 		total_gap_cycles = user_param->latency_gap * cpu_mhz;
	cycles_t 	end_cycle, start_gap;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ctx->wr[0].sg_list->length = user_param->size;
	ctx->wr[0].send_flags = IBV_SEND_SIGNALED;

	/* Duration support in latency tests. */
	if (user_param->test_type == DURATION) {
		duration_param=user_param;
		duration_param->state = START_STATE;
		signal(SIGALRM, catch_alarm);
		user_param->iters = 0;
		if (user_param->margin > 0)
			alarm(user_param->margin);
		else
			catch_alarm(0);
	}
	while (scnt < user_param->iters || (user_param->test_type == DURATION && user_param->state != END_STATE)) {
		if (user_param->latency_gap) {
			start_gap = get_cycles();
			end_cycle = start_gap + total_gap_cycles;
			while (get_cycles() < end_cycle) {
				continue;
			}
		}
		if (user_param->test_type == ITERATIONS)
			user_param->tposted[scnt++] = get_cycles();

		err = post_send_method(ctx, 0, user_param);

		if (err) {
			fprintf(stderr,"Couldn't post send: scnt=%lu\n",scnt);
			return 1;
		}

		if (user_param->test_type == DURATION && user_param->state == END_STATE)
			break;

		if (user_param->use_event) {
			if (ctx_notify_events(ctx->send_channel)) {
				fprintf(stderr, "Couldn't request CQ notification\n");
				return 1;
			}
		}

		do {
			ne = ibv_poll_cq(ctx->send_cq, 1, &wc);
			if(ne > 0) {
				if (wc.status != IBV_WC_SUCCESS) {
					//coverity[uninit_use_in_call]
					NOTIFY_COMP_ERROR_SEND(wc,scnt,scnt);
					return 1;
				}
				if (user_param->test_type==DURATION && user_param->state == SAMPLE_STATE)
					user_param->iters++;

			} else if (ne < 0) {
				fprintf(stderr, "poll CQ failed %d\n", ne);
				return FAILURE;
			}

		} while (!user_param->use_event && ne == 0);
	}

	return 0;
}

/******************************************************************************
 *
 ******************************************************************************/
int run_iter_lat_send(struct pingpong_context *ctx,struct perftest_parameters *user_param)
{
	uint64_t		scnt = 0; /* sent packets counter */
	uint64_t		rcnt = 0; /* received packets counter */
	int			poll = 0;
	int			ne;
	int			err = 0;
	struct ibv_wc		wc;
	struct ibv_recv_wr	*bad_wr_recv;

	int  			firstRx = 1;
	int 			size_per_qp = (user_param->use_srq) ?
					user_param->rx_depth/user_param->num_of_qps : user_param->rx_depth;
	int 			cpu_mhz = get_cpu_mhz(user_param->cpu_freq_f);
	int			total_gap_cycles = user_param->latency_gap * cpu_mhz;
	int			send_flows_index = 0;
	int			recv_flows_index = 0;
	cycles_t 		end_cycle, start_gap;
	uintptr_t		primary_send_addr = ctx->sge_list[0].addr;
	uintptr_t		primary_recv_addr = ctx->recv_sge_list[0].addr;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	if (user_param->connection_type != RawEth) {
		ctx->wr[0].sg_list->length = user_param->size;
		ctx->wr[0].send_flags = 0;
	}
	if (user_param->size <= user_param->inline_size) {
		ctx->wr[0].send_flags |= IBV_SEND_INLINE;
	}
	while (scnt < user_param->iters || rcnt < user_param->iters ||
			( (user_param->test_type == DURATION && user_param->state != END_STATE))) {

		/*
		 * Get the received packet. make sure that the client won't enter here until he sends
		 * his first packet (scnt < 1)
		 * server will enter here first and wait for a packet to arrive (from the client)
		 */
		if ((rcnt < user_param->iters || user_param->test_type == DURATION) && !(scnt < 1 && user_param->machine == CLIENT)) {
			if (user_param->use_event) {
				if (ctx_notify_events(ctx->recv_channel)) {
					fprintf(stderr , " Failed to notify events to CQ\n");
					return 1;
				}
			}
			do {
				ne = ibv_poll_cq(ctx->recv_cq,1,&wc);
				if (user_param->test_type == DURATION && user_param->state == END_STATE)
					break;

				if (ne > 0) {
					if (firstRx) {
						set_on_first_rx_packet(user_param);
						firstRx = 0;
					}

					if (wc.status != IBV_WC_SUCCESS) {
						//coverity[uninit_use_in_call]
						NOTIFY_COMP_ERROR_RECV(wc,rcnt);
						return 1;
					}

					rcnt++;

					if (user_param->test_type == DURATION && user_param->state == SAMPLE_STATE)
						user_param->iters++;

					/*if we're in duration mode or there
					 * is enough space in the rx_depth,
					 * post that you received a packet.
					 */
					if (user_param->test_type == DURATION || (rcnt + size_per_qp <= user_param->iters)) {
						if (user_param->use_srq) {
							if (ibv_post_srq_recv(ctx->srq, &ctx->rwr[get_wr_index(wc.wr_id)], &bad_wr_recv)) {
								fprintf(stderr, "Couldn't post recv SRQ. QP = %d: counter=%lu\n",(int)wc.qp_num, rcnt);
								return 1;
							}

						} else {
							if (ibv_post_recv(ctx->qp[get_wr_id_qp_index(wc.wr_id)], &ctx->rwr[get_wr_index(wc.wr_id)], &bad_wr_recv)) {
								fprintf(stderr, "Couldn't post recv: rcnt=%lu\n", rcnt);
								return 15;
							}
						}
						if (user_param->flows != DEF_FLOWS) {
							if (++recv_flows_index == user_param->flows) {
								recv_flows_index = 0;
								ctx->recv_sge_list[0].addr = primary_recv_addr;
							} else {
								ctx->recv_sge_list[0].addr += INC(user_param->size, ctx->cache_line_size);
							}
						}
					}
				} else if (ne < 0) {
					fprintf(stderr, "poll CQ failed %d\n", ne);
					return 1;
				}
			} while (!user_param->use_event && ne == 0);
		}

		if (scnt < user_param->iters || (user_param->test_type == DURATION && user_param->state != END_STATE)) {

			if (user_param->latency_gap) {
				start_gap = get_cycles();
				end_cycle = start_gap + total_gap_cycles;
				while (get_cycles() < end_cycle) {
					continue;
				}
			}

			if (user_param->test_type == ITERATIONS)
				user_param->tposted[scnt] = get_cycles();

			scnt++;

			if (scnt % user_param->cq_mod == 0 || (user_param->test_type == ITERATIONS && scnt == user_param->iters)) {
				poll = 1;
				ctx->wr[0].send_flags |= IBV_SEND_SIGNALED;
			}

			/* if we're in duration mode and the time is over, exit from this function */
			if (user_param->test_type == DURATION && user_param->state == END_STATE)
				break;

			/* send the packet that's in index 0 on the buffer */
			err = post_send_method(ctx, 0, user_param);

			if (err) {
				fprintf(stderr,"Couldn't post send: scnt=%lu \n",scnt);
				return 1;
			}
			if (user_param->flows != DEF_FLOWS) {
				if (++send_flows_index == user_param->flows) {
					send_flows_index = 0;
					ctx->sge_list[0].addr = primary_send_addr;
				} else {
					ctx->sge_list[0].addr = primary_send_addr + (ctx->flow_buff_size * send_flows_index);
				}
			}
			if (poll == 1) {

				struct ibv_wc s_wc;
				int s_ne;

				if (user_param->use_event) {
					if (ctx_notify_events(ctx->send_channel)) {
						fprintf(stderr , " Failed to notify events to CQ");
						return FAILURE;
					}
				}

				/* wait until you get a cq for the last packet */
				do {
					s_ne = ibv_poll_cq(ctx->send_cq, 1, &s_wc);
				} while (!user_param->use_event && s_ne == 0);

				if (s_ne < 0) {
					fprintf(stderr, "poll on Send CQ failed %d\n", s_ne);
					return FAILURE;
				}

				if (s_wc.status != IBV_WC_SUCCESS) {
					//coverity[uninit_use_in_call]
					NOTIFY_COMP_ERROR_SEND(s_wc,scnt,scnt)
						return 1;
				}
				poll = 0;
				ctx->wr[0].send_flags &= ~IBV_SEND_SIGNALED;
			}
		}
	}

	return 0;
}
/******************************************************************************
 *Server
 ******************************************************************************/
int run_iter_lat_burst_server(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	int i;
	int ne;
	int err;
	uint64_t scnt = 0;
	uint64_t rcnt = 0;
	uint64_t ccnt = 0;
	struct ibv_wc		*wc = NULL;
	struct ibv_send_wr	*bad_wr;
	struct ibv_recv_wr      *bad_wr_recv = NULL;
	int qp_index;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ALLOCATE(wc, struct ibv_wc, user_param->burst_size);

	/* main loop for polling */
	while (rcnt < user_param->iters) {

		ne = ibv_poll_cq(ctx->recv_cq, user_param->burst_size, wc);
		if (ne > 0) {
			for (i = 0; i < ne; i++) {
				qp_index = (int)get_wr_id_qp_index(wc[i].wr_id);
				if (wc[i].status != IBV_WC_SUCCESS) {
					NOTIFY_COMP_ERROR_RECV(wc[i], rcnt);
					free(wc);
					return FAILURE;
				}
				rcnt++;
				if (rcnt%user_param->reply_every == 0 && scnt - ccnt < user_param->tx_depth) {
					err = ibv_post_send(ctx->qp[0], &ctx->wr[0], &bad_wr);
					if (err) {
						fprintf(stderr, "Couldn't post send: scnt=%lu\n", scnt);
						free(wc);
						return FAILURE;
					}
					scnt++;
				}

				if (ibv_post_recv(ctx->qp[qp_index], &ctx->rwr[qp_index], &bad_wr_recv)) {
					fprintf(stderr, "Couldn't post recv Qp=%d rcnt=%lu\n", (int)wc[i].qp_num, rcnt);
					free(wc);
					return FAILURE;
				}
			}
		} else if (ne < 0) {
			fprintf(stderr, "poll CQ failed %d\n", ne);
			free(wc);
			return FAILURE;
		}
		ne = ibv_poll_cq(ctx->send_cq, CTX_POLL_BATCH, wc);
		if (ne > 0) {
			for (i = 0; i < ne; i++) {
				if (wc[i].status != IBV_WC_SUCCESS) {
					NOTIFY_COMP_ERROR_SEND(wc[i], scnt, ccnt);
					free(wc);
					return FAILURE;
				}
				ccnt++;
			}

		} else if (ne < 0) {
			fprintf(stderr, "poll CQ failed %d\n", ne);
			free(wc);
			return FAILURE;
		}
	}
	free(wc);
	return SUCCESS;
}
/******************************************************************************
 *Client
 ******************************************************************************/
int run_iter_lat_burst(struct pingpong_context *ctx, struct perftest_parameters *user_param)
{
	uint64_t		totscnt = 0; /* sent packets counter */
	uint64_t		totccnt = 0; /* complete sent packets counter */
	uint64_t		totrcnt = 0; /* received packets counter */
	uint64_t	   	tot_iters;
	uint64_t		pong_cnt = 0; /* counts how many pongs arrived */
	int			ne, ns;
	int			err = 0;
	int			i = 0;
	int			qp_index;
	struct ibv_wc		*wc;
	struct ibv_send_wr	*bad_wr;
	int			cpu_mhz;
	int			return_value = 0;
	/* Rate Limiter*/
	int			rate_limit_pps = 0;
	double			gap_time = 0;   /* in usec */
	cycles_t		gap_cycles = 0; /* in cycles */
	cycles_t		gap_deadline = 0;
	unsigned int		number_of_bursts = 0;
	int			burst_iter = 0;
	int			is_sending_burst = 0;
	struct ibv_recv_wr      *bad_wr_recv = NULL;

	#ifdef HAVE_IBV_WR_API
	if (user_param->connection_type != RawEth)
		ctx_post_send_work_request_func_pointer(ctx, user_param);
	#endif

	ALLOCATE(wc, struct ibv_wc, user_param->burst_size);

	tot_iters = (uint64_t)user_param->iters;

	/* If using rate limiter, calculate gap time between bursts */
	cpu_mhz = get_cpu_mhz(user_param->cpu_freq_f);
	if (cpu_mhz <= 0) {
		fprintf(stderr, "Failed: couldn't acquire cpu frequency for rate limiter.\n");
		return_value = FAILURE;
		goto cleaning;
	}
	if (user_param->rate_limit > 0 ) {
		if (user_param->rate_limit_type == SW_RATE_LIMIT) {
			switch (user_param->rate_units) {
				case MEGA_BYTE_PS:
					rate_limit_pps = ((double)(user_param->rate_limit) / user_param->size) * 1048576;
					break;
				case GIGA_BIT_PS:
					rate_limit_pps = ((double)(user_param->rate_limit) / (user_param->size * 8)) * 1000000000;
					break;
				case PACKET_PS:
					rate_limit_pps = user_param->rate_limit;
					break;
				default:
					fprintf(stderr, " Failed: Unknown rate limit units\n");
					return_value = FAILURE;
					goto cleaning;
			}
			number_of_bursts = rate_limit_pps / user_param->burst_size;
			gap_time = 1000000 * (1.0 / number_of_bursts);
		}
	}

	gap_cycles = cpu_mhz * gap_time;

	/* main loop for posting */
	while (totrcnt < (totscnt / user_param->reply_every) || totccnt < tot_iters) {

		if (is_sending_burst == 0) {
			if (gap_deadline > get_cycles() && user_param->rate_limit_type == SW_RATE_LIMIT) {
				/* Go right to cq polling until gap time is over. */
				goto polling;
			}
			gap_deadline = get_cycles() + gap_cycles;
			is_sending_burst = 1;
			burst_iter = 0;
		}
		while ((totscnt < user_param->iters)
			&& (totscnt - totccnt) < (user_param->tx_depth) && !(is_sending_burst == 0 )) {

			err = ibv_post_send(ctx->qp[0],&ctx->wr[0],&bad_wr);

			if (err) {
				fprintf(stderr, "Couldn't post send: scnt=%lu\n", totscnt);
				free(wc);
				return FAILURE;
			}
			if (user_param->post_list == 1 && user_param->size <= (ctx->cycle_buffer / 2)) {
				increase_loc_addr(ctx->wr[0].sg_list, user_param->size, totscnt,
					ctx->my_addr[0], 0, ctx->cache_line_size, ctx->cycle_buffer);
			}
			totscnt += user_param->post_list;
			if (totscnt % user_param->reply_every == 0 && totscnt != 0) {
				user_param->tposted[pong_cnt] = get_cycles();
				pong_cnt++;
			}
			if (++burst_iter == user_param->burst_size) {
				is_sending_burst = 0;
			}
		}
polling:
		do {
			ne = ibv_poll_cq(ctx->recv_cq, CTX_POLL_BATCH, wc);
			if (ne > 0) {
				for (i = 0; i < ne; i++) {
					qp_index = (int)get_wr_id_qp_index(wc[i].wr_id);
					user_param->tcompleted[totrcnt] = get_cycles();
					totrcnt++;
					if (wc[i].status != IBV_WC_SUCCESS) {
						NOTIFY_COMP_ERROR_SEND(wc[i], totscnt, totccnt);
						return_value = FAILURE;
						goto cleaning;
					}
					if (ibv_post_recv(ctx->qp[qp_index], &ctx->rwr[qp_index], &bad_wr_recv)) {
						fprintf(stderr, "Couldn't post recv Qp=%d rcnt=%lu\n", (int)wc[i].qp_num, totrcnt);
						return_value = FAILURE;
						goto cleaning;
					}
				}
			} else if (ne < 0) {
				fprintf(stderr, "poll CQ failed %d\n", ne);
				return_value = 1;
				goto cleaning;
			}
			ns = ibv_poll_cq(ctx->send_cq, user_param->burst_size, wc);
			if (ns > 0) {
				for (i = 0; i < ns; i++) {
					if (wc[i].status != IBV_WC_SUCCESS) {
						NOTIFY_COMP_ERROR_SEND(wc[i], totscnt, totccnt);
						return_value = FAILURE ;
						goto cleaning;
					}
					totccnt += user_param->cq_mod;
				}
			} else if (ns < 0) {
				fprintf(stderr, "poll CQ failed %d\n", ne);
				return_value = 1;
				goto cleaning;
			}
		} while (ne != 0);
	}
	free(wc);
	return SUCCESS;
cleaning:
	free(wc);
	return return_value;
}
/******************************************************************************
 *
 ******************************************************************************/
uint16_t ctx_get_local_lid(struct ibv_context *context,int port)
{
	struct ibv_port_attr attr;

	if (ibv_query_port(context,port,&attr))
		return 0;

	//coverity[uninit_use]
	return attr.lid;
}

/******************************************************************************
 *
 ******************************************************************************/
void catch_alarm(int sig)
{
	switch (duration_param->state) {
		case START_STATE:
			duration_param->state = SAMPLE_STATE;
			get_cpu_stats(duration_param,1);
			duration_param->tposted[0] = get_cycles();
			alarm(duration_param->duration - 2*(duration_param->margin));
			break;
		case SAMPLE_STATE:
			duration_param->state = STOP_SAMPLE_STATE;
			duration_param->tcompleted[0] = get_cycles();
			get_cpu_stats(duration_param,2);
			if (duration_param->margin > 0)
				alarm(duration_param->margin);
			else
				catch_alarm(0);

			break;
		case STOP_SAMPLE_STATE:
			duration_param->state = END_STATE;
			break;
		default:
			fprintf(stderr,"unknown state\n");
	}
}

void check_alive(int sig)
{
	if (check_alive_data.current_totrcnt > check_alive_data.last_totrcnt) {
		check_alive_data.last_totrcnt = check_alive_data.current_totrcnt;
		alarm(60);
	} else if (check_alive_data.current_totrcnt == check_alive_data.last_totrcnt && check_alive_data.current_totrcnt < check_alive_data.g_total_iters) {
		fprintf(stderr," Did not get Message for 120 Seconds, exiting..\n Total Received=%d, Total Iters Required=%d\n",check_alive_data.current_totrcnt, check_alive_data.g_total_iters);

		if (check_alive_data.is_events) {
			/* Can't report BW, as we are stuck in event_loop */
			fprintf(stderr," Due to this issue, Perftest cannot produce a report when in event mode.\n");
			exit(FAILURE);
		}
		else {
			/* exit nice from run_iter function and report known bw/mr */
			check_alive_data.to_exit = 1;
		}
	}
}

/******************************************************************************
 *
 ******************************************************************************/
void print_bw_infinite_mode()
{
	print_report_bw(duration_param,NULL);
	duration_param->last_iters = duration_param->iters;
	duration_param->tposted[0] = get_cycles();
}

/******************************************************************************
 *
 ******************************************************************************/
void *handle_signal_print_thread(void* duration)
{
	int* duration_p = (int*) duration;
	while(1){
		sleep(*duration_p);
		print_bw_infinite_mode();
	}

}

/******************************************************************************
 *
 ******************************************************************************/
#ifdef HAVE_PACKET_PACING
int check_packet_pacing_support(struct pingpong_context *ctx)
{
	struct ibv_device_attr_ex attr;
	memset(&attr, 0, sizeof (struct ibv_device_attr_ex));

	if (ibv_query_device_ex(ctx->context, NULL, &attr)) {
		fprintf(stderr, "ibv_query_device_ex failed\n");
		return FAILURE;
	}

	/* qp_rate_limit_max > 0 if PP is supported */
	return attr.packet_pacing_caps.qp_rate_limit_max > 0 ? SUCCESS : FAILURE;
}
#endif

int run_iter_fs(struct pingpong_context *ctx, struct perftest_parameters *user_param) {

	struct raw_ethernet_info	*my_dest_info = NULL;
	struct raw_ethernet_info	*rem_dest_info = NULL;

	struct ibv_flow			**flow_create_result;
	struct ibv_flow_attr		**flow_rules;
	int 				flow_index = 0;
	int				qp_index = 0;
	int				retval = SUCCESS;
	uint64_t			tot_fs_cnt    = 0;
	uint64_t			allocated_flows = 0;
	uint64_t			tot_iters = 0;

	/* Allocate user input dependable structs */
	ALLOCATE(my_dest_info, struct raw_ethernet_info, user_param->num_of_qps);
	memset(my_dest_info, 0, sizeof(struct raw_ethernet_info) * user_param->num_of_qps);
	ALLOCATE(rem_dest_info, struct raw_ethernet_info, user_param->num_of_qps);
	memset(rem_dest_info, 0, sizeof(struct raw_ethernet_info) * user_param->num_of_qps);

	if (user_param->test_type == ITERATIONS) {
		user_param->flows = user_param->iters * user_param->num_of_qps;
		allocated_flows = user_param->iters;
	} else if (user_param->test_type == DURATION) {
		allocated_flows = (2 * MAX_FS_PORT) - (user_param->server_port + user_param->client_port);
	}


	ALLOCATE(flow_create_result, struct ibv_flow*, allocated_flows * user_param->num_of_qps);
	ALLOCATE(flow_rules, struct ibv_flow_attr*, allocated_flows * user_param->num_of_qps);

	if(user_param->test_type == DURATION) {
		duration_param = user_param;
		user_param->iters = 0;
		duration_param->state = START_STATE;
		signal(SIGALRM, catch_alarm);
		alarm(user_param->margin);
		if (user_param->margin > 0)
			alarm(user_param->margin);
		else
			catch_alarm(0); /* move to next state */
	}
	if (set_up_fs_rules(flow_rules, ctx, user_param, allocated_flows)) {
			fprintf(stderr, "Unable to set up flow rules\n");
			retval = FAILURE;
			goto cleaning;
	}

	do {/* This loop runs once in Iteration mode */
		for (qp_index = 0; qp_index < user_param->num_of_qps; qp_index++) {

			for (flow_index = 0; flow_index < allocated_flows; flow_index++) {

				if (user_param->test_type == ITERATIONS)
					user_param->tposted[tot_fs_cnt] = get_cycles();
				else if (user_param->test_type == DURATION && duration_param->state == END_STATE)
					break;
				flow_create_result[flow_index] =
					ibv_create_flow(ctx->qp[qp_index], flow_rules[(qp_index * allocated_flows) + flow_index]);
				if (user_param->test_type == ITERATIONS)
					user_param->tcompleted[tot_fs_cnt] = get_cycles();
				if (!flow_create_result[flow_index]) {
					perror("error");
					fprintf(stderr, "Couldn't attach QP\n");
					retval = FAILURE;
					goto cleaning;
				}
				if (user_param->test_type == ITERATIONS ||
				   (user_param->test_type == DURATION && duration_param->state == SAMPLE_STATE))
					tot_fs_cnt++;
				tot_iters++;
			}
		}
	} while (user_param->test_type == DURATION && duration_param->state != END_STATE);

	if (user_param->test_type == DURATION && user_param->state == END_STATE)
		user_param->iters = tot_fs_cnt;

cleaning:
	/* destroy open flows */
	for (flow_index = 0; flow_index < tot_iters; flow_index++) {
		if (ibv_destroy_flow(flow_create_result[flow_index])) {
			perror("error");
			fprintf(stderr, "Couldn't destroy flow\n");
		}
	}
	free(flow_rules);
	free(flow_create_result);
	free(my_dest_info);
	free(rem_dest_info);

	return retval;
}


/******************************************************************************
*
******************************************************************************/
int rdma_cm_allocate_nodes(struct pingpong_context *ctx,
	struct perftest_parameters *user_param, struct rdma_addrinfo *hints)
{
	int rc = SUCCESS, i = 0;
	char *error_message;

	if (user_param->connection_type == UD
		|| user_param->connection_type == RawEth)
		hints->ai_port_space = RDMA_PS_UDP;
	else
		hints->ai_port_space = RDMA_PS_TCP;

	ALLOCATE(ctx->cma_master.nodes, struct cma_node, user_param->num_of_qps);
	if (!ctx->cma_master.nodes) {
		error_message = "Failed to allocate memory for RDMA CM nodes.";
		goto error;
	}

	memset(ctx->cma_master.nodes, 0,
		(sizeof *ctx->cma_master.nodes) * user_param->num_of_qps);

	for (i = 0; i < user_param->num_of_qps; i++) {
		ctx->cma_master.nodes[i].id = i;
		if (user_param->machine == CLIENT) {
			rc = rdma_create_id(ctx->cma_master.channel,
				&ctx->cma_master.nodes[i].cma_id, NULL, hints->ai_port_space);
			if (rc) {
				error_message = "Failed to create RDMA CM ID.";
				goto error;
			}
		}
	}

	if (user_param->has_source_ip) {
		if (AF_INET == user_param->ai_family) {
			struct sockaddr_in *source_addr;
			source_addr = calloc(1, sizeof(*source_addr));
			source_addr->sin_family = AF_INET;
			source_addr->sin_addr.s_addr = inet_addr(user_param->source_ip);

			if (source_addr->sin_addr.s_addr < 0) {
				fprintf(stderr, "Invalid source address.\n");
				return 1;
			}

			hints->ai_src_addr = (struct sockaddr *)(source_addr);
			hints->ai_src_len = sizeof(*source_addr);
		} else {
			int err = 0;
			struct sockaddr_in6 *source_addr;
			source_addr = calloc(1, sizeof(*source_addr));
			source_addr->sin6_family = AF_INET6;
			err = inet_pton(AF_INET6, user_param->source_ip, source_addr->sin6_addr.s6_addr);

			if (!err) {
				fprintf(stderr, "Invalid network address in the specified address family.\n");
				return 1;
			} else if (err < 0) {
				fprintf(stderr, "Invalid address family.\n");
				return 1;
			}

			hints->ai_src_addr = (struct sockaddr *)(source_addr);
			hints->ai_src_len = sizeof(*source_addr);
		}
	}

	return rc;

error:
	while (--i >= 0) {
		rc = rdma_destroy_id(ctx->cma_master.nodes[i].cma_id);
		if (rc) {
			error_message = "Failed to destroy RDMA CM ID.";
			break;
		}
	}

	free(ctx->cma_master.nodes);
	return error_handler(error_message);
}

/******************************************************************************
*
******************************************************************************/
void rdma_cm_destroy_qps(struct pingpong_context *ctx,
	struct perftest_parameters *user_param)
{
	int i;

	for (i = 0; i < user_param->num_of_qps; i++) {
		struct cma_node *cm_node = &ctx->cma_master.nodes[i];
		if (cm_node->cma_id->qp) {
			rdma_destroy_qp(cm_node->cma_id);
		}
	}
}

/******************************************************************************
*
******************************************************************************/
int rdma_cm_destroy_cma(struct pingpong_context *ctx,
	struct perftest_parameters *user_param)
{
	int rc = SUCCESS, i;
	char error_message[ERROR_MSG_SIZE] = "";
	struct cma_node *cm_node;

	for (i = 0; i < user_param->num_of_qps; i++) {
		cm_node = &ctx->cma_master.nodes[i];
		rc = rdma_destroy_id(cm_node->cma_id);
		if (rc) {
			sprintf(error_message,
				"Failed to destroy RDMA CM ID number %d.", i);
			goto error;
		}
	}

	rdma_destroy_event_channel(ctx->cma_master.channel);
	if (ctx->cma_master.rai) {
		rdma_freeaddrinfo(ctx->cma_master.rai);
	}

	free(ctx->cma_master.nodes);
	return rc;

error:
	return error_handler(error_message);
}

int error_handler(char *error_message)
{
	fprintf(stderr, "%s\nERRNO: %s.\n", error_message, strerror(errno));
	return FAILURE;
}

/******************************************************************************
 * End
 ******************************************************************************/
