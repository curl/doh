/*
 * https://gist.github.com/armornick/3447121
 */

#include "doh-sound.h"

static Uint8 *audio_pos; // global pointer to the audio buffer to be played
static Uint32 audio_len; // remaining length of the sample we have to play

// audio callback function
// here you have to copy the data of your audio buffer into the
// requesting audio buffer (stream)
// you should only copy as much as the requested length (len)
void my_audio_callback(void *userdata, Uint8 *stream, int len)
{
	(void)userdata;
	if (audio_len == 0) {
		return;
	}

	len = ((unsigned)len > audio_len ? (int)audio_len : len);
	SDL_memcpy(stream, audio_pos, len);

	audio_pos += len;
	audio_len -= len;
}

/*
** PLAYING A SOUND IS MUCH MORE COMPLICATED THAN IT SHOULD BE
*/
void *play_sound(void *args)
{
	(void)args;
	// Initialize SDL.
	if (SDL_Init(SDL_INIT_AUDIO) < 0) {
		return NULL;
	}

	// local variables
	static Uint32 wav_length; // length of our sample
	static Uint8 *wav_buffer; // buffer containing our audio file
	static SDL_AudioSpec wav_spec; // the specs of our piece of music

	/* Load the WAV */
	// the specs, length and buffer of our wav are filled
	if (SDL_LoadWAV(DOH_SOUND_FILE, &wav_spec, &wav_buffer, &wav_length) == NULL) {
		fprintf(stderr, "Could not load sound file %s\n", DOH_SOUND_FILE);
		return NULL;
	}

	// set the callback function
	wav_spec.callback = my_audio_callback;
	wav_spec.userdata = NULL;
	// set our global static variables
	audio_pos = wav_buffer; // copy sound buffer
	audio_len = wav_length; // copy file length

	/* Open the audio device */
	if (SDL_OpenAudio(&wav_spec, NULL) < 0) {
		fprintf(stderr, "Couldn't open audio: %s\n", SDL_GetError());
		return NULL;
	}

	/* Start playing */
	SDL_PauseAudio(0);

	// wait until we're done playing
	while (audio_len > 0) {
		SDL_Delay(10);
	}

	// shut everything down
	SDL_CloseAudio();
	SDL_FreeWAV(wav_buffer);

	return NULL;
}
